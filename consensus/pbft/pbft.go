package pbft

import (
	"io"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rpc"

	"github.com/elastos/Elastos.ELA/core/types/payload"

	"golang.org/x/crypto/sha3"
)

// Pbft is a consensus engine based on Byzantine fault-tolerant algorithm
type Pbft struct {
	dispatcher *dpos.Dispatcher
	confirmCh chan *payload.Confirm
}

func New(cfg *params.PbftConfig, logPath string) *Pbft {
	//todo init log by pbftConfig
	dpos.InitLog(0, 0, 0, logPath)
	producers := make([][]byte, len(cfg.Producers))
	for i, v := range cfg.Producers {
		producers[i] = common.Hex2Bytes(v)
	}
	confirmCh := make(chan *payload.Confirm)
	dispatcher := dpos.NewDispatcher(producers, confirmCh)
	pbft := &Pbft{
		dispatcher,
		confirmCh,
	}
	return pbft
}

func (p *Pbft) Author(header *types.Header) (common.Address, error) {
	dpos.Info("Pbft Author")
	// TODO panic("implement me")
	return header.Coinbase, nil
}

func (p *Pbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	dpos.Info("Pbft VerifyHeader")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	dpos.Info("Pbft VerifyHeaders")
	// TODO panic("implement me")
	return nil, nil
}

func (p *Pbft) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	dpos.Info("Pbft VerifyUncles")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	dpos.Info("Pbft VerifySeal")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
	dpos.Info("Pbft Prepare")
	// TODO panic("implement me")
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Difficulty = parent.Difficulty
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
	select {
	case confirm := <-p.confirmCh:
		//todo completed this
		dpos.Info("received confirm", confirm.Proposal.Hash().String())
		break
	case <-stop:
		return nil
	}

	header := block.Header()
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
	panic("implement me")
}

func (p *Pbft) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "pbft",
		Version:   "1.0",
		Service:   &API{chain: chain},
		Public:    false,
	}}
}

func (p *Pbft) Close() error {
	dpos.Info("Pbft Close")
	return nil
}

func (p *Pbft) SignersCount() int {
	dpos.Info("Pbft SignersCount")
	panic("implement me")
}

func (p *Pbft) ProposalConfirmed(confirm *payload.Confirm) {
	dpos.Info("")
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
