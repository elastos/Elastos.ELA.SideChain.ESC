package smallcrosstx

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	elaType "github.com/elastos/Elastos.ELA/core/types"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)

var (
	smallCrossTxMap = make(map[string]int)
)

func OnSmallCrossTx(arbiters []string, signature string, rawTx string) error {
	buff, err := hex.DecodeString(rawTx)
	if err != nil {
		return err
	}

	var txn elaType.Transaction
	err = txn.Deserialize(bytes.NewReader(buff))
	if err != nil {
		log.Error("[Small-Transfer] Decode transaction error", err.Error())
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	totalArbiters := len(arbiters)
	for _, pubkey := range arbiters {
		pub := common.Hex2Bytes(pubkey)
		pubKey, err := elaCrypto.DecodePoint(pub)
		if err != nil {
			log.Error("arbiter is error", "error", err)
		}
		err = elaCrypto.Verify(*pubKey, buff, sig)
		if err == nil {
			count := smallCrossTxMap[txn.Hash().String()]
			fmt.Println("NotifySmallCrossTx NotifySmallCrossTx count-----", count)
			count ++
			smallCrossTxMap[txn.Hash().String()] = count
			if count  > totalArbiters *  2 / 3{
				fmt.Println("NotifySmallCrossTx NotifySmallCrossTx -----")
				spv.NotifySmallCrossTx(txn)
			}
		}
	}
	return nil
}
