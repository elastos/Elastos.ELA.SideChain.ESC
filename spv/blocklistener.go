package spv

import (
	"bytes"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
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

func (l *BlockListener) onBlockHandled(block interface{}) {
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
			log.Error("received error block", "height", b.Height)
			return
		}

		log.Info("========================================================================================")
		log.Info("mainchain change arbiter received:")
		log.Info("----------------------------------------------------------------------------------------")
		log.Info(tx.String())
		payloadData := tx.Payload.(* payload.NextTurnDPOSInfo)
	    producers := make([][]byte, 0)
		log.Info("------------------------CRC ARbiters--------------------------\n")
		for _, arbiter := range payloadData.CRPublickeys {
			producers = append(producers, arbiter)
			log.Info(common.Bytes2Hex(arbiter) + "\n")
		}
		log.Info("-----------------------DPOSPublicKeys---------------------------\n")
		for _, arbiter := range payloadData.DPOSPublicKeys {
			producers = append(producers, arbiter)
			log.Info(common.Bytes2Hex(arbiter) + "\n")
		}
		log.Info("work height", "height", payloadData.WorkingHeight, "count", len(producers))

		nodes := []string{
			"03bfd8bd2b10e887ec785360f9b329c2ae567975c784daca2f223cb19840b51914",
			"0342eeb0d664e2507d732382c66d0eedbd0a0f989179fd33d71679aa607d5d3b57",
			"03b0a37c11d1dfa8622e3d64b9dfefee781c6eb8279fa28f0c723efbc7c67adcd8",
			"023288ae99c212b42e3ba9fa088f4578eb2c958a0c2293b900d4fdefd5e6c571ee",
			"02bd6d05a6d3d97ce3a1137f0d0c56c0d7f23c06fe04d7c85430780d440b64d88b",
			"031c0c22f6712324babd9443475c9120a51ac8813c446a84161b6b950e2c1bb0f5"}
		producers = make([][]byte, 0)
		for _, node := range nodes {
			//producers[i] = common.Hex2Bytes(v)
			producers = append(producers, common.Hex2Bytes(node))
		}
		go events.Notify(dpos.ETUpSuperNode, producers)
}