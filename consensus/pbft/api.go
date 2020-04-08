package pbft

import "github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	chain  consensus.ChainReader
}

func (a *API) GetProducers() uint64 {
	return 0
}