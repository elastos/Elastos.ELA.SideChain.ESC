// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pbft

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	dmsg "github.com/elastos/Elastos.ELA.SideChain.ESC/dpos/msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/smallcrosstx"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/withdrawfailedtx"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	ecom "github.com/elastos/Elastos.ELA/common"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/p2p/msg"

	"golang.org/x/crypto/sha3"
)

var (
	extraVanity = 32            // Fixed number of extra-data prefix bytes
	extraSeal   = 65            // Fixed number of extra-data suffix bytes reserved for signer seal
	diffInTurn  = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn  = big.NewInt(1) // Block difficulty for in-turn signatures
)

const (
	// maxRequestedBlocks is the maximum number of requested block
	// hashes to store in memory.
	maxRequestedBlocks = msg.MaxInvPerMsg
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
	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	ErrAlreadyConfirmedBlock = errors.New("already confirmed block")

	ErrWaitSyncBlock = errors.New("has confirmed, wait sync block")

	ErrInvalidConfirm = errors.New("invalid confirm")

	ErrSignerNotOnduty = errors.New("singer is not on duty")

	ErrConsensusIsRunning = errors.New("current consensus is running")

	ErrWaitRecoverStatus = errors.New("wait for recoved states")

	// errInvalidDifficulty is returned if the difficulty of a block neither 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	errChainForkBlock = errors.New("chain fork block")

	errDoubleSignBlock = errors.New("double sign block")
)

// Pbft is a consensus engine based on Byzantine fault-tolerant algorithm
type Pbft struct {
	datadir       string
	cfg           params.PbftConfig
	dispatcher    *dpos.Dispatcher
	confirmCh     chan *payload.Confirm
	unConfirmCh   chan *payload.Confirm
	account       daccount.Account
	bridgeAccount crypto.Keypair
	network       *dpos.Network
	blockPool     *dpos.BlockPool
	chain         *core.BlockChain
	timeSource    dtime.MedianTimeSource

	// IsCurrent returns whether BlockChain synced to best height.
	IsCurrent          func() bool
	StartMine          func()
	OnDuty             func()
	OnInsertChainError func(id peer.PID, block *types.Block, err error)

	requestedBlocks    map[common.Hash]struct{}
	requestedProposals map[ecom.Uint256]struct{}
	statusMap          map[uint32]map[string]*dmsg.ConsensusStatus
	notHandledProposal map[string]struct{}

	enableViewLoop bool
	recoverStarted bool
	isRecoved      bool
	period         uint64
	isSealOver     bool
	isRecovering   bool
}

func New(chainConfig *params.ChainConfig, dataDir string) *Pbft {
	logpath := filepath.Join(dataDir, "/logs/dpos")
	dposPath := filepath.Join(dataDir, "/network/dpos")
	if strings.LastIndex(dataDir, "/") == len(dataDir)-1 {
		dposPath = filepath.Join(dataDir, "network/dpos")
		logpath = filepath.Join(dataDir, "logs/dpos")
	}
	cfg := chainConfig.Pbft
	if cfg == nil {
		dpos.InitLog(0, 0, 0, logpath)
		return &Pbft{}
	}
	pbftKeystore := chainConfig.PbftKeyStore
	password := []byte(chainConfig.PbftKeyStorePassWord)
	dpos.InitLog(cfg.PrintLevel, cfg.MaxPerLogSize, cfg.MaxLogsSize, logpath)
	producers := make([][]byte, len(cfg.Producers))
	for i, v := range cfg.Producers {
		producers[i] = common.Hex2Bytes(v)
	}
	account, err := dpos.GetDposAccount(pbftKeystore, password)
	var bridgeAccount crypto.Keypair
	if err != nil {
		if string(password) == "" {
			fmt.Println("create dpos account error:", err.Error(), "pbftKeystore:", pbftKeystore, "password")
		} else {
			fmt.Println("create dpos account error:", err.Error(), "pbftKeystore:", pbftKeystore, "password", string(password))
		}
		//can't return, because common node need verify use this engine
	} else {
		bridgeAccount, err = dpos.GetBridgeAccount(pbftKeystore, password)
		if err != nil {
			if string(password) == "" {
				fmt.Println("create GetArbiterAccount error:", err.Error(), "pbftKeystore:", pbftKeystore, "password")
			} else {
				fmt.Println("create GetArbiterAccount error:", err.Error(), "pbftKeystore:", pbftKeystore, "password", string(password))
			}
		}
	}
	medianTimeSouce := dtime.NewMedianTime()

	pbft := &Pbft{
		datadir:            dataDir,
		cfg:                *cfg,
		confirmCh:          make(chan *payload.Confirm),
		unConfirmCh:        make(chan *payload.Confirm),
		account:            account,
		bridgeAccount:      bridgeAccount,
		requestedBlocks:    make(map[common.Hash]struct{}),
		requestedProposals: make(map[ecom.Uint256]struct{}),
		statusMap:          make(map[uint32]map[string]*dmsg.ConsensusStatus),
		notHandledProposal: make(map[string]struct{}),
		period:             5,
		timeSource:         medianTimeSouce,
	}
	blockPool := dpos.NewBlockPool(pbft.verifyConfirm, pbft.verifyBlock, DBlockSealHash)
	pbft.blockPool = blockPool
	var accpubkey []byte

	if account != nil {
		accpubkey = account.PublicKeyBytes()
		network, err := dpos.NewNetwork(&dpos.NetworkConfig{
			IPAddress:        cfg.IPAddress,
			Magic:            cfg.Magic,
			DefaultPort:      cfg.DPoSPort,
			Account:          account,
			MedianTime:       medianTimeSouce,
			MaxNodePerHost:   cfg.MaxNodePerHost,
			Listener:         pbft,
			DataPath:         dposPath,
			PublicKey:        accpubkey,
			GetCurrentHeight: pbft.GetMainChainHeight,
			AnnounceAddr: func() {
				events.Notify(dpos.ETAnnounceAddr, nil)
			},
		})
		if err != nil {
			dpos.Error("New dpos network error:", err.Error())
			return nil
		}
		pbft.network = network
		pbft.subscribeEvent()
	}
	pbft.dispatcher = dpos.NewDispatcher(producers, pbft.onConfirm, pbft.onUnConfirm,
		10*time.Second, accpubkey, medianTimeSouce, pbft, chainConfig.GetPbftBlock())
	return pbft
}

func (p *Pbft) GetMainChainHeight(pid peer.PID) uint64 {
	return spv.GetSpvHeight()
}

func (p *Pbft) subscribeEvent() {
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case events.ETDirectPeersChangedV2:
			peersInfo := e.Data.(*peer.PeersInfo)
			go p.network.UpdatePeers(peersInfo.CurrentPeers, peersInfo.NextPeers)
		case dpos.ETNewPeer:
			count := len(p.network.GetActivePeers())
			log.Info("new peer accept", "active peer count", count)
			height := p.chain.CurrentHeader().Number.Uint64()
			cfg := p.chain.Config()
			if cfg.PBFTBlock != nil && height >= cfg.PBFTBlock.Uint64()-cfg.PreConnectOffset && height < cfg.PBFTBlock.Uint64() {
				log.Info("before change engine AnnounceDAddr")
				go p.AnnounceDAddr()
			}

			if p.chain.Engine() == p && !p.dispatcher.GetConsensusView().HasProducerMajorityCount(count) {
				log.Info("end change engine AnnounceDAddr")
				go p.AnnounceDAddr()
			}
		case dpos.ETNextProducers:
			producers := e.Data.([]peer.PID)
			log.Info("update next producers", "totalCount", spv.GetTotalProducersCount())
			p.dispatcher.GetConsensusView().UpdateNextProducers(producers, spv.GetTotalProducersCount())
		case dpos.ETOnSPVHeight:
			height := e.Data.(uint32)
			if spv.GetWorkingHeight() >= height {
				if uint64(spv.GetWorkingHeight()-height) <= p.chain.Config().PreConnectOffset {
					curProducers := p.dispatcher.GetConsensusView().GetProducers()
					isSame := p.dispatcher.GetConsensusView().IsSameProducers(curProducers)
					if !isSame {
						go p.AnnounceDAddr()
					} else {
						log.Info("For the same batch of aribters, no need to re-connect direct net")
					}
				}
			}
		case dpos.ETSmallCroTx:
			if croTx, ok := e.Data.(*smallcrosstx.ETSmallCrossTx); ok {
				msg := dmsg.NewSmallCroTx(croTx.Signature, croTx.RawTx)
				p.BroadMessage(msg)
			}

		case dpos.ETFailedWithdrawTx:
			if failEvt, ok := e.Data.(*withdrawfailedtx.FailedWithdrawEvent); ok {
				msg := dmsg.NewFailedWithdrawTx(failEvt.Signature, failEvt.Txid)
				p.BroadMessage(msg)
			}
		}
	})
}

func (p *Pbft) IsSameProducers(curProducers [][]byte) bool {
	return p.dispatcher.GetConsensusView().IsSameProducers(curProducers)
}

func (p *Pbft) IsCurrentProducers(curProducers [][]byte) bool {
	return p.dispatcher.GetConsensusView().IsCurrentProducers(curProducers)
}

func (p *Pbft) GetDataDir() string {
	return p.datadir
}

func (p *Pbft) GetPbftConfig() params.PbftConfig {
	return p.cfg
}

func (p *Pbft) CurrentBlock() *types.Block {
	if p.chain == nil {
		return nil
	}
	return p.chain.CurrentBlock()
}

func (p *Pbft) GetBlockByHeight(height uint64) *types.Block {
	if p.chain == nil {
		return nil
	}
	return p.chain.GetBlockByNumber(height)
}

func (p *Pbft) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

func (p *Pbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	dpos.Info("Pbft VerifyHeader")
	return p.verifyHeader(chain, header, nil, seal)
}

func (p *Pbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	dpos.Info("Pbft VerifyHeaders")
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			var err error
			//Check header is verified
			if seals[i] {
				// Don't waste time checking blocks from the future
				if header.Time > uint64(time.Now().Unix()) {
					err = consensus.ErrFutureBlock
				}
			}
			if err == nil && !p.IsInBlockPool(p.SealHash(header)) {
				err = p.verifyHeader(chain, header, headers[:i], seals[i])
			} else if err == nil {
				err = p.verifySeal(chain, header, headers[:i])
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

func (p *Pbft) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header, seal bool) error {

	if header.Number == nil || header.Number.Uint64() == 0 {
		return errUnknownBlock
	}
	// Don't waste time checking blocks from the future
	if seal && header.Time > uint64(time.Now().Unix()) {
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
	log.Info("verify header HasConfirmed", "seal:", seal, "height", header.Number)
	if !seal && p.dispatcher.GetFinishedHeight() == number {
		log.Warn("verify header already confirm block")
		return ErrAlreadyConfirmedBlock
	}

	if parent.Time+p.period > header.Time {
		return ErrInvalidTimestamp
	}

	if number > 0 {
		if header.Difficulty == nil || (header.Difficulty.Cmp(diffInTurn) != 0) {
			return errInvalidDifficulty
		}
	}

	if seal {
		return p.verifySeal(chain, header, parents)
	}

	return nil
}

func (p *Pbft) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	dpos.Info("Pbft VerifyUncles")
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
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

	// Retrieve the confirm from the header extra-data
	var confirm payload.Confirm
	err := confirm.Deserialize(bytes.NewReader(header.Extra))
	if err != nil {
		return err
	}
	err = p.verifyConfirm(&confirm, header.Nonce.Uint64())
	if err != nil {
		return err
	}

	if oldHeader := chain.GetHeaderByNumber(number); oldHeader != nil {
		var oldConfirm payload.Confirm
		err := oldConfirm.Deserialize(bytes.NewReader(oldHeader.Extra))
		if err != nil {
			return nil
		}

		if confirm.Proposal.ViewOffset < oldConfirm.Proposal.ViewOffset && number < chain.CurrentHeader().Number.Uint64() {
			log.Warn("verify seal chain fork", "oldViewOffset", oldConfirm.Proposal.ViewOffset, "newViewOffset", confirm.Proposal.ViewOffset, "height", number)
			return errChainForkBlock
		}
		if confirm.Proposal.ViewOffset == oldConfirm.Proposal.ViewOffset && oldHeader.Hash() != header.Hash() {
			return errDoubleSignBlock
		}
	}

	return nil
}

func (p *Pbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
	log.Info("Pbft Prepare:", "height:", header.Number.Uint64(), "parent", header.ParentHash.String())
	p.isSealOver = false
	nowTime := uint64(time.Now().Unix())
	if p.dispatcher != nil {
		nowTime = uint64(p.dispatcher.GetNowTime().Unix())
	}
	header.Difficulty = p.CalcDifficulty(chain, nowTime, nil)
	if p.dispatcher != nil {
		header.Nonce = types.EncodeNonce(p.dispatcher.GetConsensusView().GetSpvHeight())
	}
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	if !p.isRecoved {
		return ErrWaitRecoverStatus
	}
	if p.dispatcher.GetConsensusView().IsRunning() && p.enableViewLoop {
		return ErrConsensusIsRunning
	}
	p.Start(parent.Time)
	if !p.IsOnduty() {
		return ErrSignerNotOnduty
	}
	if header.Number.Uint64() <= p.dispatcher.GetFinishedHeight() {
		return ErrAlreadyConfirmedBlock
	}
	header.Time = parent.Time + p.period
	if header.Time < nowTime {
		header.Time = nowTime
		p.dispatcher.ResetView(nowTime)
	}

	return nil
}

func (p *Pbft) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header) {
	dpos.Info("Pbft Finalize:", "height:", header.Number.Uint64())
	sealHash := p.SealHash(header)
	hash, _ := ecom.Uint256FromBytes(sealHash.Bytes())
	p.dispatcher.FinishedProposal(header.Number.Uint64(), *hash, header.Time)
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)
	p.CleanFinalConfirmedBlock(header.Number.Uint64())
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
	dpos.Info("Pbft Seal:", block.NumberU64())
	if p.account == nil {
		return errors.New("no signer inited")
	}

	if !p.isRecoved {
		return ErrWaitRecoverStatus
	}

	parent := chain.GetHeader(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}

	if block.NumberU64() <= p.dispatcher.GetFinishedHeight() {
		return ErrAlreadyConfirmedBlock
	}
	if !p.IsProducer() {
		return errUnauthorizedSigner
	}
	if !p.IsOnduty() {
		return ErrSignerNotOnduty
	}
	p.BroadBlockMsg(block)

	if err := p.StartProposal(block); err != nil {
		return err
	}
	p.isSealOver = false
	header := block.Header()
	//Waiting for statistics of voting results
	delay := time.Unix(int64(header.Time), 0).Sub(p.dispatcher.GetNowTime())
	log.Info("wait seal time", "delay", delay)
	time.Sleep(delay)
	changeViewTime := p.dispatcher.GetConsensusView().GetChangeViewTime()
	toleranceDelay := changeViewTime.Sub(p.dispatcher.GetNowTime())
	log.Info("changeViewLeftTime", "toleranceDelay", toleranceDelay)
	select {
	case confirm := <-p.confirmCh:
		log.Info("Received confirmCh", "proposal", confirm.Proposal.Hash().String(), "block:", block.NumberU64())
		p.addConfirmToBlock(header, confirm)
		p.isSealOver = true
		break
	case <-p.unConfirmCh:
		log.Warn("proposal is rejected")
		p.isSealOver = true
		return nil
	case <-time.After(toleranceDelay):
		log.Warn("seal time out stop mine")
		p.isSealOver = true
		return nil
	case <-stop:
		log.Warn("pbft seal is stop")
		p.isSealOver = true
		return nil
	}
	finalBlock := block.WithSeal(header)
	go func() {
		select {
		case results <- finalBlock:
			p.BroadBlockMsg(finalBlock)
			p.CleanFinalConfirmedBlock(block.NumberU64())
		default:
			dpos.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

func (p *Pbft) addConfirmToBlock(header *types.Header, confirm *payload.Confirm) error {
	sealBuf := new(bytes.Buffer)
	if err := confirm.Serialize(sealBuf); err != nil {
		log.Error("confirm serialize error", "error", err)
		return err
	}
	header.Extra = make([]byte, sealBuf.Len())
	copy(header.Extra[:], sealBuf.Bytes()[:])
	sealHash := SealHash(header)
	hash, _ := ecom.Uint256FromBytes(sealHash.Bytes())
	p.dispatcher.FinishedProposal(header.Number.Uint64(), *hash, header.Time)
	return nil
}

func (p *Pbft) onConfirm(confirm *payload.Confirm) error {
	log.Info("--------[onConfirm]------", "proposal:", confirm.Proposal.Hash())
	if p.isSealOver && p.IsOnduty() {
		log.Warn("seal block is over, can't confirm")
		return errors.New("seal block is over, can't confirm")
	}
	err := p.blockPool.AppendConfirm(confirm)
	if err != nil {
		log.Error("Received confirm", "proposal", confirm.Proposal.Hash().String(), "err:", err)
		return err
	}
	if p.IsOnduty() {
		log.Info("on duty, set confirm block")
		p.confirmCh <- confirm
	} else {
		log.Info("not on duty, not broad confirm block")
	}

	return err
}

func (p *Pbft) onUnConfirm(unconfirm *payload.Confirm) error {
	log.Info("--------[onUnConfirm]------", "proposal:", unconfirm.Proposal.Hash())
	if p.isSealOver {
		return errors.New("seal block is over, can't unconfirm")
	}
	if p.IsOnduty() {
		p.unConfirmCh <- unconfirm
	}
	return nil
}

func (p *Pbft) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

func (p *Pbft) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	dpos.Info("Pbft CalcDifficulty")
	if p.IsOnduty() {
		return diffInTurn
	}
	return diffNoTurn
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
	p.enableViewLoop = false
	return nil
}

func (p *Pbft) SignersCount() int {
	dpos.Info("Pbft SignersCount")
	count := p.dispatcher.GetConsensusView().GetTotalProducersCount()
	return count
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

func DBlockSealHash(block dpos.DBlock) (hash ecom.Uint256, err error) {
	if b, ok := block.(*types.Block); ok {
		hasher := sha3.NewLegacyKeccak256()
		encodeSigHeader(hasher, b.Header())
		hasher.Sum(hash[:0])
		return hash, nil
	} else {
		return ecom.EmptyHash, errors.New("verifyBlock errror, block is not ethereum block")
	}
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

func (p *Pbft) AddDirectLinkPeer(pid peer.PID, addr string) {
	if p.network != nil {
		p.network.AddDirectLinkAddr(pid, addr)
	}
}

func (p *Pbft) GetActivePeersCount() int {
	if p.network != nil {
		return len(p.network.GetActivePeers())
	}
	return 0
}

func (p *Pbft) StartServer() {
	if p.network != nil {
		p.network.Start()
		p.Recover()
	}
}

func (p *Pbft) StopServer() {
	if p.network != nil {
		p.network.Stop()
	}
	p.enableViewLoop = false
}

func (p *Pbft) Start(headerTime uint64) {
	if p.account == nil {
		return
	}
	if !p.enableViewLoop {
		p.enableViewLoop = true
		p.dispatcher.GetConsensusView().SetChangViewTime(headerTime)
		p.dispatcher.GetConsensusView().UpdateDutyIndex(p.chain.CurrentBlock().NumberU64())
		go p.changeViewLoop()
	} else {
		p.dispatcher.ResetView(headerTime)
	}
	p.dispatcher.GetConsensusView().SetRunning()
}

func (p *Pbft) changeViewLoop() {
	for p.enableViewLoop {
		p.network.PostChangeViewTask()
		time.Sleep(1 * time.Second)
	}
}

func (p *Pbft) Recover() {
	if p.IsCurrent == nil || p.account == nil || p.isRecovering ||
		!p.dispatcher.IsProducer(p.account.PublicKeyBytes()) {
		log.Info(" Recover Error")
		p.dispatcher.GetConsensusView().DumpInfo()
		return
	}
	p.isRecovering = true
	for {
		if p.IsCurrent() && len(p.network.GetActivePeers()) > 0 &&
			p.dispatcher.GetConsensusView().HasArbitersMinorityCount(len(p.network.GetActivePeers())) {
			log.Info("----- PostRecoverTask --------")
			p.network.PostRecoverTask()
			p.isRecovering = false
			return
		}
		time.Sleep(time.Second)
	}
}

func (p *Pbft) IsOnduty() bool {
	if p.account == nil {
		return false
	}
	return p.dispatcher.ProducerIsOnDuty()
}

func (p *Pbft) IsProducer() bool {
	if p.account == nil {
		return false
	}
	return p.dispatcher.IsProducer(p.account.PublicKeyBytes())
}

func (p *Pbft) SetBlockChain(chain *core.BlockChain) {
	p.chain = chain
}

func (p *Pbft) GetBlockChain() *core.BlockChain {
	return p.chain
}

func (p *Pbft) broadConfirmMsg(confirm *payload.Confirm, height uint64) {
	msg := dmsg.NewConfirmMsg(confirm, height)
	p.BroadMessage(msg)
}

func (p *Pbft) verifyConfirm(confirm *payload.Confirm, elaHeight uint64) error {
	minSignCount := 0
	if elaHeight == 0 {
		minSignCount = p.dispatcher.GetConsensusView().GetCRMajorityCount()
	} else {
		_, count, err := spv.GetProducers(elaHeight)
		if err != nil {
			return err
		}
		minSignCount = p.dispatcher.GetConsensusView().GetMajorityCountByTotalSigners(count)
	}
	err := dpos.CheckConfirm(confirm, minSignCount)
	return err
}

func (p *Pbft) verifyBlock(block dpos.DBlock) error {
	if p.chain == nil {
		return errors.New("pbft chain is nil")
	}
	if b, ok := block.(*types.Block); ok {
		err := p.VerifyHeader(p.chain, b.Header(), false)
		if err != nil {
			return err
		}
		err = p.chain.Validator().ValidateBody(b)
		if err != nil {
			log.Error("validateBody error", "height:", b.GetHeight())
			return err
		}
	} else {
		return errors.New("verifyBlock errror, block is not ethereum block")
	}

	return nil
}

func (p *Pbft) IsInBlockPool(hash common.Hash) bool {
	if u256, err := ecom.Uint256FromBytes(hash.Bytes()); err == nil {
		_, suc := p.blockPool.GetBlock(*u256)
		return suc
	}
	return false
}

func (p *Pbft) CleanFinalConfirmedBlock(height uint64) {
	p.blockPool.CleanFinalConfirmedBlock(height)
}

func (p *Pbft) OnViewChanged(isOnDuty bool, force bool) {
	if isOnDuty && p.OnDuty != nil {
		p.OnDuty()
	}
	proposal := p.dispatcher.UpdatePrecociousProposals()
	if proposal != nil {
		log.Info("UpdatePrecociousProposals process proposal")
		p.OnProposalReceived(peer.PID{}, proposal)
	}

	if !force {
		p.dispatcher.CleanProposals(true)
		if p.IsCurrent() && isOnDuty {
			log.Info("---------startMine()-------")
			p.dispatcher.GetConsensusView().SetReady()
			p.StartMine()
		}
	}
}

func (p *Pbft) GetTimeSource() dtime.MedianTimeSource {
	return p.timeSource
}

func (p *Pbft) IsBadBlock(height uint64) bool {
	blocks := p.chain.BadBlocks()
	for _, block := range blocks {
		if block.GetHeight() == height {
			return true
		}
	}
	return false
}

func (p *Pbft) GetDposAccount() daccount.Account {
	return p.account
}

func (p *Pbft) IsOnDuty() bool {
	return p.dispatcher.ProducerIsOnDuty()
}
