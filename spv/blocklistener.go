package spv

import (
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

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
	if l.blockNumber >= l.param.height {
		log.Info("NotifyBlock ETOnSPVHeight Notify", "l.blockNumber", l.blockNumber)
		events.Notify(dpos.ETOnSPVHeight, l.blockNumber)
		l.StoreAuxBlock(block)
		log.Info("BlockListener handle block ", "height", block.Height)
		l.onBlockHandled(l.param.block)
		if l.handle != nil {
			l.handle(l.param.block)
		}
	}
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

func (l *BlockListener) onBlockHandled(block interface{})  {
	if nextTurnDposInfo == nil {
		InitNextTurnDposInfo()
	}
}
func InitNextTurnDposInfo() {
	//workingHeight, crcArbiters, normalArbiters, err := SpvService.GetNextArbiters()
	//if err != nil {
	//	log.Error("GetNextArbiters error", "err", err.Error())
	//	return
	//}
	//nextTurnDposInfo = &payload.NextTurnDPOSInfo{
	//	WorkingHeight: workingHeight,
	//	CRPublicKeys: crcArbiters,
	//	DPOSPublicKeys: normalArbiters,
	//}
	//peers := DumpNextDposInfo()
	//events.Notify(dpos.ETNextProducers, peers)
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