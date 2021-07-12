package spv

import (
	"bytes"
	spv "github.com/elastos/Elastos.ELA.SPV/interface"
	"github.com/elastos/Elastos.ELA.SPV/util"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	eevent "github.com/elastos/Elastos.ELA.SideChain.ETH/core/events"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
)

type auxParam struct {
	block  *util.Block
	height uint32
}

func (param *auxParam) clean() {
	param.height = 0
	param.block = nil
}

type BlockListener struct {
	blockNumber uint32
	param       auxParam
	handle      func(block interface{}) error
}

func (l *BlockListener) NotifyBlock(block *util.Block) {
	l.blockNumber = block.Height
	l.StoreAuxBlock(block)
	log.Info("BlockListener handle block ", "height", l.blockNumber)
	l.onBlockHandled(l.param.block)
	if l.handle != nil {
		l.handle(l.param.block)
	}
	events.Notify(dpos.ETOnSPVHeight, l.blockNumber)
}

func (l *BlockListener) BlockHeight() uint32 {
	return l.blockNumber
}

func (l *BlockListener) StoreAuxBlock(block interface{}) {
	b := block.(*util.Block)

	l.param = auxParam{
		b,
		b.Height,
	}
}

func (l *BlockListener) RegisterFunc(handleFunc func(block interface{}) error) {
	l.handle = handleFunc
}

func (l *BlockListener) onBlockHandled(block interface{}) {
	isWorkingHeight := SpvIsWorkingHeight()
	if nextTurnDposInfo == nil {
		InitNextTurnDposInfo()
		isWorkingHeight = SpvIsWorkingHeight()
	} else if !isWorkingHeight {
		if IsNexturnBlock(block) {
			log.Info("------------------ force change next turn arbiters-----------")
			peers := DumpNextDposInfo()
			events.Notify(dpos.ETNextProducers, peers)
		} else if consensusMode == spv.POW {
			//SpvService.mux.Post(eevent.InitCurrentProducers{})//note: add this ,will use current producers to seal block
			//InitNextTurnDposInfo()
		}
	}
	if nextTurnDposInfo == nil {
		return
	}
	if len(nextTurnDposInfo.CRPublicKeys) == 0 && len(nextTurnDposInfo.DPOSPublicKeys) == 0 && consensusMode == spv.DPOS {
		consensusMode = spv.POW
		log.Info("<----------MainChain turn to POW consensus mode------->")
	} else if (len(nextTurnDposInfo.CRPublicKeys) > 0 || len(nextTurnDposInfo.DPOSPublicKeys) > 0) &&  consensusMode == spv.POW && isWorkingHeight {
		log.Info("<----------MainChain turn to DPOS consensus mode------->")
		consensusMode = spv.DPOS
	}

	if isWorkingHeight {
		SpvService.mux.Post(eevent.InitCurrentProducers{})
	}
}

func IsNexturnBlock(block interface{}) bool {
	b := block.(*util.Block)
	var tx types.Transaction
	for _, t := range b.Transactions {
		buf := new(bytes.Buffer)
		t.Serialize(buf)
		r := bytes.NewReader(buf.Bytes())
		tx = types.Transaction{}
		tx.Deserialize(r)
		if tx.TxType == types.NextTurnDPOSInfo {
			break
		}
	}

	if  tx.TxType != types.NextTurnDPOSInfo {
		log.Info("received not next turn block", "height", b.Height)
		return false
	}

	payloadData := tx.Payload.(* payload.NextTurnDPOSInfo)
	nextTurnDposInfo.WorkingHeight = payloadData.WorkingHeight
	nextTurnDposInfo.CRPublicKeys = payloadData.CRPublicKeys
	nextTurnDposInfo.DPOSPublicKeys = payloadData.DPOSPublicKeys

	return true
}

func InitNextTurnDposInfo() {
	workingHeight, crcArbiters, normalArbiters, err := SpvService.GetNextArbiters()
	if err != nil {
		log.Error("GetNextArbiters error", "err", err.Error())
		return
	}

	nextTurnDposInfo = &payload.NextTurnDPOSInfo{
		WorkingHeight: workingHeight,
		CRPublicKeys: crcArbiters,
		DPOSPublicKeys: normalArbiters,
	}
	peers := DumpNextDposInfo()
	events.Notify(dpos.ETNextProducers, peers)
}

func DumpNextDposInfo() []peer.PID {
	log.Info("-------------------dump next turn aribiters---------------")
	log.Info("-------------------CRPublicKeys---------------")
	peers := make([]peer.PID, 0)
	for _, arbiter := range nextTurnDposInfo.CRPublicKeys {
		if len(arbiter) > 0 {
			var pid peer.PID
			copy(pid[:], arbiter)
			peers = append(peers, pid)
		}
		log.Info(common.Bytes2Hex(arbiter) + "\n")
	}
	log.Info("-------------------DPOSPublicKeys---------------")
	for _, arbiter := range nextTurnDposInfo.DPOSPublicKeys {
		if len(arbiter) > 0 {
			var pid peer.PID
			copy(pid[:], arbiter)
			peers = append(peers, pid)
		}
		log.Info(common.Bytes2Hex(arbiter) + "\n")
	}
	log.Info("work height", "height", nextTurnDposInfo.WorkingHeight, "activeCount", len(peers), "count", GetTotalProducersCount())
	return peers
}