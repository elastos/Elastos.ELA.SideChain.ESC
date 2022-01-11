package chainbridge_core

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	engine *pbft.Pbft
}

func (a *API) HasProducerMajorityCount(count, total int) bool {
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

	log.Info("UpdateArbiters ", "len", len(list), "total", total,
		"producers", a.engine.GetTotalArbitersCount(), "sigCount", count)
	if a.HasProducerMajorityCount(count, total) || IsFirstUpdateArbiter && a.HasProducerMajorityCount(len(list), total) {
		sigs := make([][]byte, 0)
		for ar, sig := range signatures {
			log.Info("signature arbiter", "arbiter", ar)
			sigs = append(sigs, sig)
		}
		log.Info("MsgReleayer.UpdateArbiters")
		err := MsgReleayer.UpdateArbiters(list, a.engine.GetTotalArbitersCount(), sigs, chainID)
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

func (a *API) GetCollectedArbiterList() []common.Address {
	arbiters := arbiterManager.GetArbiterList()

	address := make([]common.Address, 0)
	for _, arbiter := range arbiters {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			return address
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		address = append(address, addr)
	}
	return address
}

func (a *API) GetSuperSigner(chainID uint8) common.Address {
	address := MsgReleayer.GetCurrentSuperSigner(chainID)
	return address
}

func (a *API) GetSuperNodePublickey(chainID uint8) string {
	nodePbk := MsgReleayer.GetSuperSignerNodePublickey(chainID)
	return nodePbk
}
