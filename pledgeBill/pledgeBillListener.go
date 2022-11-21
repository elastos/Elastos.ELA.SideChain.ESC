package pledgeBill

import (
	"fmt"
	"github.com/elastos/Elastos.ELA.SPV/bloom"
	spv "github.com/elastos/Elastos.ELA.SPV/interface"
	"github.com/elastos/Elastos.ELA/common"
	elacom "github.com/elastos/Elastos.ELA/core/types/common"
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
)

type PledgeBillListener struct {
	Service spv.SPVService
}

func (l *PledgeBillListener) Address() string {
	return ""
}

func (l *PledgeBillListener) Type() elacom.TxType {
	return elacom.CreateNFT
}

func (l *PledgeBillListener) Flags() uint64 {
	return spv.FlagNotifyInSyncing | spv.FlagNotifyConfirmed
}

func (l *PledgeBillListener) Notify(id common.Uint256, proof bloom.MerkleProof, tx it.Transaction) {
	if !tx.IsCreateNFTTX() {
		return
	}
	fmt.Println(">>>>>>>>>>>>>>>>>> pledgeBillListener Nofify BEGIN <<<<<<<<<<<<<<<<<<<<<<<<")
	ProcessPledgedBill(tx)
	fmt.Println("mainchain create nft tx", tx.String())
	l.Service.SubmitTransactionReceipt(id, tx.Hash()) // give spv service a receipt, Indicates receipt of notice
	fmt.Println(">>>>>>>>>>>>>>>>>> pledgeBillListener Nofify END <<<<<<<<<<<<<<<<<<<<<<<<")
}
