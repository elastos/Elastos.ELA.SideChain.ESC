package chainbridge_core

import (
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
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

func (a *API) UpdateArbiters(chainID uint64) error {
	collection := arbiterManager.GetCollection()
	list := collection.List
	total := collection.NextTotalCount
	signatures := collection.Signatures
	producersCount := collection.CurrentTotalCount
	sigCount := len(signatures)

	if len(a.engine.GetCurrentProducers()) == 1 && sigCount == 0 {
		sigCount = 1 //use to single node to consensus
	}

	bridgelog.Info("UpdateArbiters ", "len", len(list), "total", total,
		"producersCount", producersCount, "sigCount", sigCount)

	if !currentArbitersHasself() && !IsFirstUpdateArbiter {
		bridgelog.Info("self is not in contract arbiter list")
		return errors.New("self is not in contract arbiter list")
	}

	if a.HasProducerMajorityCount(len(list), total) {
		if a.HasProducerMajorityCount(sigCount, producersCount) || IsFirstUpdateArbiter {
			sigs := make([][]byte, 0)
			for ar, sig := range signatures {
				log.Info("signature arbiter", "arbiter", ar)
				sigs = append(sigs, sig)
			}
			log.Info("MsgReleayer.UpdateArbiters")
			err := MsgReleayer.UpdateArbiters(list, total, sigs, chainID)
			if err != nil {
				log.Error("UpdateArbiters error", "error", err)
				return err
			}
			return nil
		}
	} else {
		bridgelog.Info("The arbiter list is not bigger than 2 / 3")
		//if spv.GetCurrentConsensusMode() != _interface.POW {
		//	go eevents.Notify(dpos_msg.ETESCStateChanged, spv.ChainState_Error)
		//}
	}

	return errors.New("the arbiter list is not bigger than 2 / 3")
}

type Arbiters struct {
	List  []common.Address
	Total uint64
	State uint8
}

func (a *API) GetArbiters(chainID uint64) *Arbiters {
	address := MsgReleayer.GetArbiters(chainID)
	for _, addr := range address {
		log.Info("GetArbiters", "address", addr.String())
	}

	msg := new(Arbiters)
	msg.List = address

	count, _ := MsgReleayer.GetTotalCount(chainID)
	msg.Total = count
	msg.State, _ = MsgReleayer.GetESCState(chainID)
	return msg
}

type Message struct {
	UpdateList     []common.Address
	Signatures     []string
	Total          int
	ConsensusTotal int
	ConsensusList  []common.Address
}

func (a *API) GetCollectedArbiterList() *Message {
	collection := arbiterManager.GetCollection()
	arbiters := collection.List
	total := collection.NextTotalCount
	signatures := collection.Signatures
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
	msg.UpdateList = address
	msg.Total = total
	msg.ConsensusTotal = collection.CurrentTotalCount
	msg.Signatures = sigs

	consensusArbiters := arbiterManager.GetConsensusArbiters()
	consensuAddress := make([]common.Address, 0)
	for _, arbiter := range consensusArbiters.List {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			return msg
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		consensuAddress = append(consensuAddress, addr)
	}
	msg.ConsensusList = consensuAddress

	return msg
}

func (a *API) InitArbiterList(arbiters []common.Address, total int, chainID uint64) error {
	err := MsgReleayer.SetArbiterList(arbiters, total, chainID)
	if err != nil {
		return err
	}
	return nil
}

func (a *API) GetSignerAddress() string {
	return a.engine.GetBridgeArbiters().Address()
}
