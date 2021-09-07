package spv

import (
	"bytes"
	spv "github.com/elastos/Elastos.ELA.SPV/interface"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	eevent "github.com/elastos/Elastos.ELA.SideChain.ESC/core/events"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

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
	return
	if block.Height <= l.blockNumber {
		log.Warn("BlockListener handle block ", "height", l.blockNumber)
		return
	}
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
	} else if !isWorkingHeight {
		if IsNexturnBlock(block) {
			log.Info("------------------ force change next turn arbiters-----------")
			peers := DumpNextDposInfo()
			events.Notify(dpos.ETNextProducers, peers)
		} else {
			InitNextTurnDposInfo()
		}
	}
	if nextTurnDposInfo == nil {
		return
	}
	nowConsensus := GetCurrentConsensusMode()
	if consensusMode == spv.POW && nowConsensus == spv.DPOS {
		log.Info("----------turn to Dpos mode------------")
		SpvService.mux.Post(eevent.InitCurrentProducers{})
		InitNextTurnDposInfo()
	} else if consensusMode == spv.DPOS && nowConsensus == spv.POW {
		log.Info("----------turn to POW mode------------")
		SpvService.mux.Post(eevent.InitCurrentProducers{})
		InitNextTurnDposInfo()
	}
	if SpvIsWorkingHeight() && nowConsensus != spv.POW {
		SpvService.mux.Post(eevent.InitCurrentProducers{})
	}
	consensusMode = nowConsensus
	log.Info("current consensus mode", "mode", consensusMode)
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

	if GetCurrentConsensusMode() == spv.POW && len(crcArbiters) == 0 && len(normalArbiters) == 0 {
		log.Info("current consensus is pow and next turn is pow", "consensusMode", consensusMode)
		if consensusMode == spv.DPOS {
			DumpNextDposInfo()
		}
		return
	}

	if isSameNexturnArbiters(workingHeight, crcArbiters, normalArbiters) {
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

func isSameNexturnArbiters(workingHeight uint32, crcArbiters, normalArbiters [][]byte) bool {
	if nextTurnDposInfo == nil {
		return false
	}
	if nextTurnDposInfo.WorkingHeight != workingHeight {
		return false
	}
	if len(crcArbiters) != len(nextTurnDposInfo.CRPublicKeys) {
		return false
	}
	if len(normalArbiters) != len(nextTurnDposInfo.DPOSPublicKeys) {
		return false
	}
	for index, v := range crcArbiters {
		if !bytes.Equal(v, nextTurnDposInfo.CRPublicKeys[index][:]) {
			return false
		}
	}
	for index, v := range normalArbiters {
		if !bytes.Equal(v, nextTurnDposInfo.DPOSPublicKeys[index][:]) {
			return false
		}
	}
	return true
}

//func (v *ConsensusView) IsSameProducers(curProducers[][]byte) bool {
//	nextProducers := v.producers.nextProducers
//	if len(curProducers) != len(nextProducers) {
//		return false
//	}
//	sort.Slice(nextProducers, func(i, j int) bool {
//		return bytes.Compare(nextProducers[i][:], nextProducers[j][:]) < 0
//	})
//
//	sort.Slice(curProducers, func(i, j int) bool {
//		return bytes.Compare(curProducers[i], curProducers[j]) < 0
//	})
//
//	for index, v := range curProducers {
//		if !bytes.Equal(v, nextProducers[index][:]) {
//			return false
//		}
//	}
//	return true
//}

func GetCurrentConsensusMode() spv.ConsensusAlgorithm {
	if SpvService == nil {
		log.Error("Spv is not started")
		return spv.DPOS
	}
	spvHeight := uint32(GetSpvHeight())
	mode , err := SpvService.GetConsensusAlgorithm(spvHeight)
	log.Info("GetCurrentConsensusMode", "error", err, "spvHeight", spvHeight)
	if err != nil {
		return spv.DPOS
	}
	return mode
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