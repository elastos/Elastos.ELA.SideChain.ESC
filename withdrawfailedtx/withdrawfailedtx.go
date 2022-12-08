package withdrawfailedtx

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"math/big"
	"strings"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/event"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"

	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/events"
)

var (
	mulFailedMux    sync.RWMutex
	failedTxList    = make(map[string][]string)
	verifiedArbiter = make(map[string][]string)

	eventMux *event.TypeMux

	FailedTxPre = "Failed_pre"

	ErrNoSignature = "not have signatures"
)

type FailedWithdrawEvent struct {
	Signature string
	Txid      string
}

//Spv database initialization
func FailedWithrawInit(datadir string, evtMux *event.TypeMux) {
	eventMux = evtMux
}

func OnProcessFaildWithdrawTx(hash string) {
	if hash[:2] == "0x" {
		hash = hash[2:]
	}
	if len(failedTxList[hash]) > 0 {
		delete(failedTxList, hash)
		delete(verifiedArbiter, hash)
	}
}

func ReceivedFailedWithdrawTx(hash string, signature string) error {
	log.Info("[ReceivedFailedWithdrawTx]", "hash", hash, "signature", signature)
	if hash[:2] == "0x" {
		hash = hash[2:]
	}
	mulFailedMux.Lock()
	defer mulFailedMux.Unlock()

	if IsSignatureVerified(hash, signature) {
		return errors.New("all ready received this tx")
	}

	client := spv.GetClient()
	if client == nil {
		return errors.New("ipc client is null")
	}

	txhash, err := client.StorageAt(context.Background(), common.Address{}, common.HexToHash(hash), nil)
	if err != nil {
		log.Error(fmt.Sprintf("%s get StorageAt: %v", hash, err))
		return err
	}

	receipt, err := client.TransactionReceipt(context.Background(), common.HexToHash(hash))
	if err != nil {
		return err
	}
	if receipt.Status == 0 {
		return errors.New("tx receipt status is 0")
	}

	h := common.Hash{}
	if common.BytesToHash(txhash) != h {
		OnProcessFaildWithdrawTx(hash)
		return errors.New("all ready refund this amount" + common.BytesToHash(txhash).String())
	}
	arbiters, total, err := spv.GetArbiters()
	if err != nil {
		return err
	}

	verifiedSigList := failedTxList[hash]
	verifiedArbiterList := verifiedArbiter[hash]
	if len(verifiedArbiterList) >= getMaxArbitersSign(total) {
		return errors.New("all ready received 2/3 signatures")
	}

	if res, arb := verifySignature(arbiters, hash, signature); res == true {
		verifiedSigList = append(verifiedSigList, signature)
		verifiedArbiterList = append(verifiedArbiterList, arb)
		failedTxList[hash] = verifiedSigList
		verifiedArbiter[hash] = verifiedArbiterList
		if len(verifiedArbiterList) >= getMaxArbitersSign(total) {
			err := SendRefundTx(spv.GetDefaultSingerAddr(), hash)
			if err != nil {
				log.Error("SendRefundTx error", "error", err)
			}
			return nil
		}
		broadFailedWithdrawEvt(hash, signature)
	} else {
		log.Error("verify signature error", "txid", hash, "signature", signature)
	}
	return nil
}

func SendRefundTx(from common.Address, txid string) error {
	addr := common.Address{}
	if from.String() == addr.String() {
		err := errors.New("SendRefundTx error signer" + from.String())
		return err
	}
	client := spv.GetClient()
	if client == nil {
		return errors.New("SendRefundTx client is not init")
	}
	failedTxHash := common.HexToHash(txid)
	result, err := client.StorageAt(context.Background(), common.Address{}, failedTxHash, nil)
	if err != nil {
		log.Error(fmt.Sprintf("%s SendRefundTx StorageAt: %v", txid, err))
		return err
	}
	emptyHash := common.Hash{}
	ethHash := common.BytesToHash(result)
	if bytes.Compare(result, emptyHash.Bytes()) != 0 {
		err = errors.New(fmt.Sprintf("%s submit by: %s", txid, ethHash.String()))
		return err
	}
	data, err := getTxData(failedTxHash)
	if err != nil {
		return err
	}
	msg := ethereum.CallMsg{From: from, To: &common.Address{}, Data: data}
	gasLimit, err := client.EstimateGas(context.Background(), msg)
	if err != nil {
		err = errors.New(fmt.Sprintf("SendRefundTx EstimateGas:%s, %v", txid, err))
		return err
	}
	if gasLimit == 0 {
		log.Error("IpcClient EstimateGas is 0:", "txid", txid)
		err = errors.New(fmt.Sprintf("IpcClient EstimateGas is 0:%s", txid))
		return err
	}
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Error("IpcClient SuggestGasPrice is err:", "txid", txid, "err", err)
		return err
	}
	log.Info("SuggestGasPrice", "value:", gasPrice)
	if gasPrice.Uint64() == 0 {
		gasPrice = big.NewInt(1000000000)
	}

	callmsg := ethereum.TXMsg{From: from, To: &common.Address{}, Data: data, Gas: gasLimit, GasPrice: gasPrice}
	hash, err := client.SendPublicTransaction(context.Background(), callmsg)
	log.Info("send refund tx", "txHash", hash, "withdrawTx", txid, "gasPrice", gasPrice.Uint64(), "gasLimit", gasLimit)
	return err
}

func getTxData(txid common.Hash) ([]byte, error) {
	data := make([]byte, 0)
	data = append(data, txid.Bytes()...)
	signatures, err := getFailedTx(txid.String())
	if err != nil {
		return []byte{}, err
	}
	for _, sig := range signatures {
		sigdata := common.Hex2Bytes(sig)
		data = append(data, sigdata...)
	}
	return data, nil
}

func GetRefundEventHash() common.Hash {
	Uint256, _ := abi.NewType("uint256", "", nil)
	String, _ := abi.NewType("string", "", nil)
	refundEvent := abi.Event{Name: "Refund", RawName: "Refund", Inputs: abi.Arguments{{Name: "from", Type: String, Indexed: false}, {Name: "to", Type: String, Indexed: false}, {Name: "value", Type: Uint256, Indexed: false}}}
	return refundEvent.ID()
}

func VerifySignatures(input []byte) bool {
	client := spv.GetClient()
	if client == nil || len(input) <= 32 {
		return false
	}
	failedTxHash := common.BytesToHash(input[0:32])
	result, err := client.StorageAt(context.Background(), common.Address{}, failedTxHash, nil)
	if err != nil {
		log.Error(fmt.Sprintf("%s VerifySignatures StorageAt: %v", failedTxHash.String(), err))
		return false
	}

	h := common.Hash{}
	if common.BytesToHash(result) != h {
		log.Error(fmt.Sprintf("all ready refund this amount %v", failedTxHash.String()))
		return false
	}

	arbiters, total, err := spv.GetArbiters()
	if err != nil {
		return false
	}

	data := input[32:]
	if len(data)%64 != 0 {
		log.Error("tx payload data is error")
		return false
	}
	signatures := make([]string, 0)
	size := len(data) / 64
	for i := 0; i < size; i++ {
		sig := data[i*64 : i*64+64]
		signatures = append(signatures, common.Bytes2Hex(sig))
	}

	if len(signatures) <= 0 {
		return false
	}
	count := 0
	txid := failedTxHash.String()
	txid = txid[2:]

	verifiedArbiterList := verifiedArbiter[txid]
	if len(verifiedArbiterList) >= getMaxArbitersSign(total) {
		log.Info("all ready verified refund withdraw tx", "txid", txid)
		return true
	}

	buff := common.Hex2Bytes(txid)
	for _, signature := range signatures {
		sig := common.Hex2Bytes(signature)
		for _, arbiter := range arbiters {
			pub := common.Hex2Bytes(arbiter)
			pubKey, err := elaCrypto.DecodePoint(pub)
			if err != nil {
				log.Error("arbiter is error", "error", err)
				continue
			}
			err = elaCrypto.Verify(*pubKey, buff, sig)
			if err == nil {
				count++
				break
			}
		}
		log.Info(">>>> verified true ", "count", count, "arbiter", "txid", txid)
		if count >= getMaxArbitersSign(total) {
			return true
		}
	}

	return false
}

func GetWithdrawTxValue(txid string) (string, *big.Int, error) {
	value := big.NewInt(0)
	client := spv.GetClient()
	if client == nil {
		return "", value, errors.New("ipc client is null")
	}
	txHash := common.HexToHash(txid)

	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		return "", value, err
	}
	abiJson := `[{"constant":false,"inputs":[{"name":"_addr","type":"string"},{"name":"_amount","type":"uint256"},{"name":"_fee","type":"uint256"}],"name":"receivePayload","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":false,"name":"_addr","type":"string"},{"indexed":false,"name":"_amount","type":"uint256"},{"indexed":false,"name":"_crosschainamount","type":"uint256"},{"indexed":true,"name":"_sender","type":"address"}],"name":"PayloadReceived","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"_sender","type":"address"},{"indexed":false,"name":"_amount","type":"uint256"},{"indexed":true,"name":"_black","type":"address"}],"name":"EtherDeposited","type":"event"}]`
	contract, err := abi.JSON(strings.NewReader(abiJson))
	evtId := contract.Events["PayloadReceived"].ID().String()

	type PayloadReceived struct {
		Addr             string
		Amount           *big.Int
		Crosschainamount *big.Int
	}
	var ev PayloadReceived
	var fromAccount string
	for _, log := range receipt.Logs {
		if log.Topics[0].String() == evtId {
			fromAccount = log.Topics[1].String()
			err := contract.Unpack(&ev, "PayloadReceived", log.Data)
			if err != nil {
				return "", value, err
			}
			value = ev.Amount
			break
		}
	}
	log.Info("GetWithdrawTxValue", "txid", txid, "value", value.String(), "sender", fromAccount)
	return fromAccount, value, nil
}

func verifySignature(arbiters []string, txid, signature string) (bool, string) {
	buff := common.Hex2Bytes(txid)
	sig := common.Hex2Bytes(signature)
	for _, arbiter := range arbiters {
		if IsArbiterVerified(txid, arbiter) {
			continue
		}
		pub := common.Hex2Bytes(arbiter)
		pubKey, err := elaCrypto.DecodePoint(pub)
		if err != nil {
			log.Error("arbiter is error", "error", err)
			return false, ""
		}
		err = elaCrypto.Verify(*pubKey, buff, sig)
		if err == nil {
			return true, arbiter
		}
	}
	return false, ""
}

func IsSignatureVerified(txid, signature string) bool {
	verifyedSigList := failedTxList[txid]
	for _, sig := range verifyedSigList {
		if sig == signature {
			return true
		}
	}
	return false
}

func IsArbiterVerified(txid, arbiter string) bool {
	arbiterList := verifiedArbiter[txid]
	for _, arb := range arbiterList {
		if arb == arbiter {
			return true
		}
	}
	return false
}

func getMaxArbitersSign(total int) int {
	return total*2/3 + 1
}

func broadFailedWithdrawEvt(hash, signature string) {
	if eventMux == nil {
		return
	}
	evt := FailedWithdrawEvent{
		Signature: signature,
		Txid:      hash,
	}
	go eventMux.Post(evt)

	go events.Notify(dpos.ETFailedWithdrawTx, &evt)
}

func IsWithdawFailedTx(input []byte, withdrawAddress string) (bool, string) {
	if len(input) <= 32 {
		return false, ""
	}
	hashData := input[0:32]
	txid := hexutil.Encode(hashData)
	client := spv.GetClient()
	if client == nil {
		return false, txid
	}

	tx, _, err := client.TransactionByHash(context.Background(), common.HexToHash(txid))
	if err != nil {
		return false, txid
	}
	if tx != nil && tx.To().String() == withdrawAddress {
		return true, txid
	}
	return false, txid
}

func getFailedTx(txid string) ([]string, error) {
	if txid[:2] == "0x" {
		txid = txid[2:]
	}
	list := failedTxList[txid]
	if len(list) > 0 {
		return list, nil
	}
	return list, errors.New("not have tx:" + txid)
}
