package smallcrosstx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/events"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/event"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	elatx "github.com/elastos/Elastos.ELA/core/transaction"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)

var (
	mulCountPti sync.RWMutex

	eventMux *event.TypeMux

	smallCrossTxCountMap = make(map[string]int)

	verifiedArbiter = make(map[string][]string)

	smallCrossTxMsgMap = make(map[string]bool)

	smallCrossTxDb = make(map[string][]byte)

	SmallTxDB_SIG_PRE = "small_cross_sig"

	SmallTxDB_TX_PRE = "small_cross_tx"

	SmallTxDB_SIGCOUNT_PRE = "small_cross_sigcount"

	SmallTxDB_BLOCKHEIGHT_PRE = "small_cross_blockNumber"

	ErrNotFound = "leveldb: not found"

	ErrAllReadyConfirm = errors.New("smallCroTxConfirmed")
)

//Spv database initialization
func SmallCrossTxInit(datadir string, evtMux *event.TypeMux) {
	eventMux = evtMux
}

func OnSmallCrossTx(arbiters []string, total int, signature, rawTx string,
	blockNumber uint64) error {
	if smallCrossTxDb == nil || eventMux == nil {
		return errors.New("smallCrossTxDb is nil")
	}
	if smallCrossTxMsgMap[rawTx] == true {
		return ErrAllReadyConfirm
	}
	buff, err := hex.DecodeString(rawTx)
	if err != nil {
		return err
	}
	r := bytes.NewReader(buff)
	txn, err := elatx.GetTransactionByBytes(r)
	err = txn.Deserialize(r)
	if err != nil {
		log.Error("[Small-Transfer] Decode transaction error", err.Error())
		return err
	}
	count := 0
	ctx := GetSmallCrossTxMsg(txn.Hash().String())
	if ctx != nil {
		if ctx.VerifiedSignature(signature) {
			return errors.New("verified this signature")
		}
		count = len(ctx.Signatures)
	}
	maxSignCount := GetMaxArbitersSign(total)
	if count >= maxSignCount {
		return ErrAllReadyConfirm
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}
	mulCountPti.Lock()
	defer mulCountPti.Unlock()
	for _, pubkey := range arbiters {
		if isArbiterVerified(pubkey, txn.Hash().String()) {
			continue
		}
		pub := common.Hex2Bytes(pubkey)
		pubKey, err := elaCrypto.DecodePoint(pub)
		if err != nil {
			log.Error("arbiter is error", "error", err)
			return err
		}
		err = elaCrypto.Verify(*pubKey, buff, sig)
		if err == nil {
			if count == 0 {
				err = PutSmallTxData(rawTx, txn.Hash().String())
				if err != nil {
					return err
				}
			}
			count++
			log.Info("OnSmallCrossTx verified ", "count", count, "maxSignCount", maxSignCount)
			if count <= maxSignCount {
				err = PutSmallTxSignature(signature, txn.Hash().String(), count-1, blockNumber)
				if err != nil {
					return err
				}
				list := verifiedArbiter[txn.Hash().String()]
				verifiedArbiter[txn.Hash().String()] = append(list, pubkey)
				smallCrossTxCountMap[txn.Hash().String()] = count
			}
			break
		}
	}
	if count >= maxSignCount {
		smallCrossTxMsgMap[rawTx] = true
		delete(verifiedArbiter, txn.Hash().String())
		eventMux.Post(events.CmallCrossTx{Tx: txn})
	}
	return nil
}

func GetMaxArbitersSign(total int) int {
	return total*2/3 + 1
}

func OnReceivedSmallCroTxFromDirectNet(arbiters [][]byte, total int, signature,
	rawTx string, blockHeight uint64) {
	list := make([]string, len(arbiters))
	for i, arbiter := range arbiters {
		list[i] = common.Bytes2Hex(arbiter)
	}
	err := OnSmallCrossTx(list, total, signature, rawTx, blockHeight)
	if err != nil {
		log.Error("OnReceivedSmallCroTxFromDirectNet", "OnSmallCrossTx error", err)
	}
}

func isArbiterVerified(arbiter string, txid string) bool {
	list := verifiedArbiter[txid]
	for _, pbk := range list {
		if pbk == arbiter {
			return true
		}
	}
	return false
}

func PutSmallTxData(rawTx string, elaHash string) error {
	if smallCrossTxDb == nil {
		return errors.New("smallCrossTxDb is nil")
	}
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	key := SmallTxDB_TX_PRE + elaHash
	smallCrossTxDb[key] = []byte(rawTx)
	return nil
}

func PutSmallTxSignature(signature string, elaHash string, count int,
	blockNumber uint64) error {
	if smallCrossTxDb == nil {
		return errors.New("smallCrossTxDb is nil")
	}
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	keyCount := SmallTxDB_SIGCOUNT_PRE + elaHash
	smallCrossTxDb[keyCount] = IntToBytes(uint64(count))

	num := strconv.Itoa(count)
	key := SmallTxDB_SIG_PRE + elaHash + num
	smallCrossTxDb[key] = []byte(signature)

	key = SmallTxDB_BLOCKHEIGHT_PRE + elaHash
	smallCrossTxDb[key] = IntToBytes(blockNumber)
	return nil
}

func GetArbiterSignCount(elaHash string) (int, error) {
	if smallCrossTxDb == nil {
		return 0, errors.New("smallCrossTxDb is nil")
	}
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	keyCount := SmallTxDB_SIGCOUNT_PRE + elaHash
	if data, ok := smallCrossTxDb[keyCount]; ok {
		count := BytesToInt(data)
		return int(count), nil
	}
	err := errors.New("can not find this small transaction:" + elaHash)
	return 0, err
}

func GetReiceivedBlockHeight(elaHash string) (uint64, error) {
	if smallCrossTxDb == nil {
		return 0, errors.New("smallCrossTxDb is nil")
	}
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	key := SmallTxDB_BLOCKHEIGHT_PRE + elaHash
	if data, ok := smallCrossTxDb[key]; ok {
		height := BytesToInt(data)
		return height, nil
	}
	err := errors.New("can not find this small transaction:" + elaHash)
	return 0, err
}

func GetSmallCrossTxMsg(elaHash string) *SmallCrossTx {
	if smallCrossTxDb == nil {
		return nil
	}
	mulCountPti.Lock()
	defer mulCountPti.Unlock()
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	key := SmallTxDB_TX_PRE + elaHash
	rawTxData := smallCrossTxDb[key]
	if len(rawTxData) == 0 {
		log.Error("GetSmallCrossTxMsg rawTx failed", "elaHash", elaHash)
		return nil
	}

	count, err := GetArbiterSignCount(elaHash)
	if err != nil {
		log.Error("GetArbiterSignCount failed", "elaHash", elaHash, "error", err)
		return nil
	}
	sigList := make([]string, 0)
	for i := 0; i <= count; i++ {
		num := strconv.Itoa(i)
		key = SmallTxDB_SIG_PRE + elaHash + num
		data := smallCrossTxDb[key]
		if len(data) == 0 {
			log.Error("GetSmallCrossTxMsg signature failed", "elaHash", elaHash, "index", i, "count", count)
			return nil
		}
		sigList = append(sigList, string(data))
	}

	height, err := GetReiceivedBlockHeight(elaHash)
	if err != nil {
		log.Error("GetReiceivedBlockHeight failed", "elaHash", elaHash, "error", err)
		return nil
	}

	msg := SmallCrossTx{
		RawTxID:     elaHash,
		RawTx:       string(rawTxData),
		Signatures:  sigList,
		BlockHeight: height,
	}
	return &msg
}

func GetSmallCrossTxBytes(elaHash string) ([]byte, *SmallCrossTx, error) {
	tx := GetSmallCrossTxMsg(elaHash)
	if tx == nil {
		return []byte{}, nil, errors.New("not have this small cross tx:" + elaHash)
	}
	data := bytes.NewBuffer([]byte{})
	err := tx.Serialize(data)
	if err != nil {
		return []byte{}, tx, errors.New("small cross tx serialize error:" + err.Error())
	}
	return data.Bytes(), tx, nil
}

func IntToBytes(n uint64) []byte {
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, n)
	return buffer.Bytes()
}

func BytesToInt(b []byte) uint64 {
	buffer := bytes.NewBuffer(b)
	var n uint64
	binary.Read(buffer, binary.BigEndian, &n)
	return n
}

func OnSmallTxSuccess(elaHash string) {
	if smallCrossTxDb == nil {
		return
	}
	if elaHash[:2] == "0x" {
		elaHash = elaHash[2:]
	}
	count, err := GetArbiterSignCount(elaHash)
	if err != nil {
		log.Info("GetArbiterSignCount error", "error", err)
		return
	}
	key := ""
	for i := 0; i <= count; i++ {
		num := strconv.Itoa(i)
		key = SmallTxDB_SIG_PRE + elaHash + num
		delete(smallCrossTxDb, key)
	}
	keyCount := SmallTxDB_SIGCOUNT_PRE + elaHash
	delete(smallCrossTxDb, keyCount)

	key = SmallTxDB_TX_PRE + elaHash
	rawTxData := smallCrossTxDb[key]
	delete(smallCrossTxMsgMap, string(rawTxData))
	delete(smallCrossTxDb, key)

	key = SmallTxDB_BLOCKHEIGHT_PRE + elaHash
	delete(smallCrossTxDb, key)
	if smallCrossTxCountMap[elaHash] > 0 {
		delete(smallCrossTxCountMap, elaHash)
	}
	if _, ok := verifiedArbiter[elaHash]; ok {
		delete(verifiedArbiter, elaHash)
	}
}
