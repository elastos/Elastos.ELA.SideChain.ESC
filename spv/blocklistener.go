package spv

import (
	"bytes"
	"github.com/elastos/Elastos.ELA.SPV/util"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/core/types/payload"
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
		log.Info("------------------------CRC ARbiters--------------------------\n")
		for _, arbiter := range payloadData.CRPublickeys {
			log.Info(common.Bytes2Hex(arbiter) + "\n")
		}
		log.Info("-----------------------DPOSPublicKeys---------------------------\n")
		for _, arbiter := range payloadData.DPOSPublicKeys {
			log.Info(common.Bytes2Hex(arbiter) + "\n")
		}
		log.Info("work height", "height", payloadData.WorkingHeight)
}