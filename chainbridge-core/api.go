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

func (a *API) UpdateArbiters(chainID uint64) uint64 {
	list := arbiterManager.GetArbiterList()
	total := arbiterManager.GetTotalCount()
	signatures := arbiterManager.GetSignatures()
	count := len(signatures)

	if len(a.engine.GetCurrentProducers()) == 1 && count == 0 {
		count = 1
	}

	log.Info("UpdateArbiters ", "len", len(list), "total", total,
		"producers", a.engine.GetTotalArbitersCount(), "sigCount", count)
	if a.HasProducerMajorityCount(len(list), total) {
		if a.HasProducerMajorityCount(count, total) || IsFirstUpdateArbiter {
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
	} else {
		log.Info("The arbiter list is not bigger than 2 / 3")
	}

	return 0
}

func (a *API) GetArbiters(chainID uint64) []common.Address {
	address := MsgReleayer.GetArbiters(chainID)
	for _, addr := range address {
		log.Info("GetArbiters", "address", addr.String())
	}
	return address
}

type Message struct {
	List       []common.Address
	Signatures []string
	Total      int
}

func (a *API) GetCollectedArbiterList() *Message {
	arbiters := arbiterManager.GetArbiterList()
	total := arbiterManager.GetTotalCount()
	signatures := arbiterManager.GetSignatures()
	msg := new(Message)
	address := make([]common.Address, 0)

	sigs := make([]string, 0)
	for _, sig := range signatures {
		sigs = append(sigs, common.Bytes2Hex(sig))
	}

	for _, arbiter := range arbiters {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			return msg
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		address = append(address, addr)
	}
	msg.List = address
	msg.Total = total
	msg.Signatures = sigs
	return msg
}

func (a *API) InitArbiterList(arbiters []common.Address, total int, chainID uint64) uint8 {
	err := MsgReleayer.SetArbiterList(arbiters, total, chainID)
	if err != nil {
		return 0
	}
	return 1
}

func (a *API) GetSuperSigner(chainID uint64) common.Address {
	address := MsgReleayer.GetCurrentSuperSigner(chainID)
	return address
}

func (a *API) GetSuperNodePublickey(chainID uint64) string {
	nodePbk := MsgReleayer.GetSuperSignerNodePublickey(chainID)
	return nodePbk
}
