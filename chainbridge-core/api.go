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

func (a *API) HasProducerMajorityCount(count, total int) bool  {
	minSignCount := int(float64(total) * 2 / 3)
	return count > minSignCount
}

func (a *API) UpdateArbiters(chainID uint8) uint64 {
	list := arbiterManager.GetArbiterList()
	total := arbiterManager.GetTotalCount()
	signatures := arbiterManager.GetSignatures()
	count := len(signatures)

	if len(a.engine.GetCurrentProducers()) == 1 && count == 0 {
		count = 1
	}

	log.Info("UpdateArbiters ","len", len(list), "total", total, "producers", a.engine.GetTotalArbitersCount(), "sigCount", count)
	if a.HasProducerMajorityCount(count, total) || IsFirstUpdateArbiter && len(list) == total {
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