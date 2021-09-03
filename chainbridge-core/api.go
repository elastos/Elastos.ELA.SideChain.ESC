package chainbridge_core

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	engine *pbft.Pbft
}

func (a *API) UpdateArbiters(chainID uint8) uint64 {
	list := arbiterManager.GetArbiterList()
	total := arbiterManager.GetTotalCount()
	if !a.engine.IsProducer() {
		log.Error("self is not a producer")
		return 0
	}
	signatures := arbiterManager.GetSignatures()
	count := len(signatures)
	log.Info("UpdateArbiters ","len", len(list), "total", total, "producers", len(a.engine.GetCurrentProducers()), "sigCount", count)
	if a.engine.HasProducerMajorityCount(count) {
		sigs := make([][]byte, 0)
		for ar, sig := range signatures {
			log.Info("signature arbiter", "arbiter", ar)
			sigs = append(sigs, sig)
		}
		err := MsgReleayer.UpdateArbiters(list, total, sigs, chainID)
		if err != nil {
			log.Error("UpdateArbiters error", "error", err)
			return 0
		}
		return 1
	}
	return 0
}

func (a *API) GetArbiters(chainID uint8) []common.Address {
	address := MsgReleayer.GetArbiters(chainID)
	for _, addr := range address {
		log.Info("GetArbiters", "address", addr.String())
	}
	return address
}