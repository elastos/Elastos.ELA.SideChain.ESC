package pbft

import (
	"io"
	"math/big"

	"golang.org/x/crypto/sha3"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/pbft/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rpc"
)

// Pbft is a consensus engine based on Byzantine fault-tolerant algorithm
type Pbft struct {
}

func New() *Pbft {
	log.Init(0, 0, 0)
	return &Pbft{}
}

func (p *Pbft) Author(header *types.Header) (common.Address, error) {
	log.Info("Pbft Author")
	// TODO panic("implement me")
	return header.Coinbase, nil
}

func (p *Pbft) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	log.Info("Pbft VerifyHeader")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	log.Info("Pbft VerifyHeaders")
	// TODO panic("implement me")
	return nil, nil
}

func (p *Pbft) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	log.Info("Pbft VerifyUncles")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	log.Info("Pbft VerifySeal")
	// TODO panic("implement me")
	return nil
}

func (p *Pbft) Prepare(chain consensus.ChainReader, header *types.Header) error {
	log.Info("Pbft Prepare")
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
	log.Info("Pbft Finalize")
	// TODO panic("implement me")
}

func (p *Pbft) FinalizeAndAssemble(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction,
	uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	log.Info("Pbft FinalizeAndAssemble")
	// No block rewards in DPoS, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts), nil
}

func (p *Pbft) Seal(chain consensus.ChainReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	log.Info("Pbft Seal")
	header := block.Header()
	go func() {
		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

func (p *Pbft) SealHash(header *types.Header) common.Hash {
	log.Info("Pbft SealHash")
	return SealHash(header)
}

func (p *Pbft) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	log.Info("Pbft CalcDifficulty")
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
	log.Info("Pbft Close")
	return nil
}

func (p *Pbft) SignersCount() int {
	log.Info("Pbft SignersCount")
	panic("implement me")
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
