package pbft

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/clique"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rpc"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/events"

	"golang.org/x/crypto/sha3"
)

var (
	extraVanity = 32 // Fixed number of extra-data prefix bytes
	extraSeal   = 64 // Fixed number of extra-data suffix bytes reserved for signer seal
)

var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")
	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")
	// to contain a 64 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 64 byte signature suffix missing")
	// errUnauthorizedSigner is returned if a header is signed by a non-authorized entity.
	errUnauthorizedSigner = errors.New("unauthorized signer")
)

// Pbft is a consensus engine based on Byzantine fault-tolerant algorithm
type Pbft struct {
	datadir    string
	cfg        params.PbftConfig
	dispatcher *dpos.Dispatcher
	confirmCh  chan *payload.Confirm
	account    daccount.Account
	netWork   *dpos.Network
}

func New(cfg *params.PbftConfig, pbftKeystore string, password []byte, dataDir string) *Pbft {
	logpath := filepath.Join(dataDir, "/logs/dpos")
	dposPath := filepath.Join(dataDir, "/network/dpos")
	if strings.LastIndex(dataDir, "/") == len(dataDir)-1 {
		dposPath = filepath.Join(dataDir, "network/dpos")
		logpath = filepath.Join(dataDir, "logs/dpos")
	}
	if cfg == nil {
		dpos.InitLog(0, 0, 0, logpath)
		return &Pbft{}
	}
	dpos.InitLog(cfg.PrintLevel, cfg.MaxPerLogSize, cfg.MaxLogsSize, logpath)
	producers := make([][]byte, len(cfg.Producers))
	for i, v := range cfg.Producers {
		producers[i] = common.Hex2Bytes(v)
	}
	confirmCh := make(chan *payload.Confirm)
	dispatcher := dpos.NewDispatcher(producers, confirmCh)
	var network *dpos.Network
	account, err := dpos.GetDposAccount(pbftKeystore, password)
	if err != nil {
		dpos.Warn("create dpos account error:", err.Error())
	} else {
		network, err = dpos.NewNetwork(&dpos.NetworkConfig{
			IPAddress:   cfg.IPAddress,
			Magic:       cfg.Magic,
			DefaultPort: cfg.DPoSPort,
			Account:     account,
			MedianTime:  dtime.NewMedianTime(),
			Listener:    nil,
			DataPath: 	 dposPath,
			ProposalDispatcher: dispatcher,
			PublicKey: account.PublicKeyBytes(),
			AnnounceAddr: func() {
				events.Notify(dpos.ETAnnounceAddr, nil)
			},
		})
		if err != nil {
			dpos.Error("New dpos network error:", err.Error())
			return nil
		}
	}

	pbft := &Pbft{
		dataDir,
		*cfg,
		dispatcher,
		confirmCh,
		account,
		network,
	}

	return pbft
}

func (p *Pbft) GetDataDir() string {
	return p.datadir
}

func (p *Pbft) GetPbftConfig() params.PbftConfig {
	return p.cfg
}

func (p *Pbft) Author(header *types.Header) (common.Address, error) {
	dpos.Info("Pbft Author")
	// TODO panic("implement me")
	return header.Coinbase, nil
}

func (p *Pbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	dpos.Info("Pbft VerifyHeader")
	return p.verifyHeader(chain, header, nil)
}

func (p *Pbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	dpos.Info("Pbft VerifyHeaders")
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := p.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (p *Pbft) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {

	if header.Number == nil || header.Number.Uint64() == 0 {
		return errUnknownBlock
	}
	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}

	// Verify that the gas limit is <= 2^63-1
	cap := uint64(0x7fffffffffffffff)
	if header.GasLimit > cap {
		return fmt.Errorf("invalid gasLimit: have %v, max %v", header.GasLimit, cap)
	}
	// Verify that the gasUsed is <= gasLimit
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("invalid gasUsed: have %d, gasLimit %d", header.GasUsed, header.GasLimit)
	}
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in Pbft
	if header.UncleHash != types.CalcUncleHash(nil) {
		return errInvalidUncleHash
	}

	number := header.Number.Uint64()
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	return p.verifySeal(chain, header, parents)
}

func (p *Pbft) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	dpos.Info("Pbft VerifyUncles")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	dpos.Info("Pbft VerifySeal")
	return p.verifySeal(chain, header, nil)
}

func (p *Pbft) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal+extraVanity {
		return errMissingSignature
	}

	publicKey := header.Extra[extraVanity : len(header.Extra)-extraSeal]
	pubkey, err := crypto.DecodePoint(publicKey)
	if err != nil {
		return err
	}

	if !p.dispatcher.GetProducers().IsProducers(publicKey) {
		return errUnauthorizedSigner
	}
	//TODO check header by confirm msg

	signature := header.Extra[len(header.Extra)-extraSeal:]
	err = crypto.Verify(*pubkey, clique.CliqueRLP(header), signature)

	return err
}

func (p *Pbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
	dpos.Info("Pbft Prepare")
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = parent.Difficulty
	header.Time = uint64(time.Now().Unix())

	// Ensure the extra data has all its components 32 + 65
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	if p.account != nil {
		signer := p.account.PublicKeyBytes()
		header.Extra = append(header.Extra, signer[:]...)
		header.Extra = append(header.Extra, make([]byte, extraSeal)...)
	}

	return nil
}

func (p *Pbft) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	dpos.Info("Pbft Finalize")
	// TODO panic("implement me")
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
}

func (p *Pbft) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	dpos.Info("Pbft FinalizeAndAssemble")
	// No block rewards in DPoS, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

func (p *Pbft) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	dpos.Info("Pbft Seal")
	time.Sleep(2 * time.Second) //todo delete me, 2-second one block to test
	if p.account == nil {
		return errors.New("no signer inited")
	}
	if !p.dispatcher.GetProducers().IsOnduty(p.account.PublicKeyBytes()) {
		return errors.New("singer is not on duty:" + common.Bytes2Hex(p.account.PublicKeyBytes()))
	}

	hash, err := elacom.Uint256FromBytes(block.Hash().Bytes())
	if err != nil {
		return err
	}
	proposal, err := dpos.StartProposal(p.account, *hash)
	if err != nil {
		log.Error("Start proposal error:", err)
		return err
	}
	//fixme The following code is used to test out the block, should used p2p network
	err = p.dispatcher.ProcessProposal(proposal)
	if err != nil {
		log.Error("ProcessProposal error:", err)
		return err
	}
	phash := proposal.Hash()
	vote, err := dpos.StartVote(&phash, true, p.account)
	if err != nil {
		log.Error("StartVote error:", err)
		return err
	}
	go func() {
		_, _, err = p.dispatcher.ProcessVote(vote)
		if err != nil {
			log.Error("ProcessVote error:", err)
		}
	}()

	select {
	case confirm := <-p.confirmCh:
		log.Info("Received confirm :", confirm.Proposal.Hash().String())
		break
	case <-time.After(5 * time.Second):
		log.Warn("Seal block is Timeout, to change view")
		p.dispatcher.FinishedProposal()
		results <- nil
		return errors.New("seal block timeout")
	case <-stop:
		return nil
	}

	header := block.Header()
	// Sign all the things!
	length := len(header.Extra)
	signature := p.account.Sign(clique.CliqueRLP(header))
	copy(header.Extra[length-extraSeal:], signature)
	go func() {
		select {
		case results <- block.WithSeal(header):
		default:
			dpos.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

func (p *Pbft) SealHash(header *types.Header) common.Hash {
	dpos.Info("Pbft SealHash")
	return SealHash(header)
}

func (p *Pbft) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	dpos.Info("Pbft CalcDifficulty")
	return big.NewInt(1)
}

func (p *Pbft) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "pbft",
		Version:   "1.0",
		Service:   &API{chain: chain, pbft: p},
		Public:    false,
	}}
}

func (p *Pbft) Close() error {
	dpos.Info("Pbft Close")
	return nil
}

func (p *Pbft) SignersCount() int {
	dpos.Info("Pbft SignersCount")
	return p.dispatcher.GetProducers().GetProducersCount()
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		//header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}
func (p *Pbft) StartServer() {
	if p.netWork != nil {
		p.netWork.Start()
	}
}

func (p *Pbft) StopServer() {
	if p.netWork != nil {
		p.netWork.Stop()
	}
}

func (p *Pbft) AddDirectLinkPeer(pid peer.PID, addr string) {
	if p.netWork != nil {
		p.netWork.AddDirectLinkAddr(pid, addr)
	}
}