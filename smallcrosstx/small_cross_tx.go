package smallcrosstx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb/leveldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/event"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"

	elaType "github.com/elastos/Elastos.ELA/core/types"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)

var (
	mulMsgPti sync.RWMutex

	mulCountPti sync.RWMutex

	eventMux *event.TypeMux

	smallCrossTxCountMap = make(map[string]int)

	verifiedArbiter = make(map[string][]string)

	smallCrossTxMsgMap = make(map[string]bool)

	smallCrossTxDb *leveldb.Database

	SmallTxDB_SIG_PRE = "small_cross_sig"

	SmallTxDB_TX_PRE = "small_cross_tx"

	SmallTxDB_SIGCOUNT_PRE = "small_cross_sigcount"

	ErrNotFound = "leveldb: not found"

	ErrAllReadyConfirm = errors.New("smallCroTxConfirmed")
)

//Spv database initialization
func SmallCrossTxInit(datadir string, evtMux *event.TypeMux) {
	db, err := leveldb.New(filepath.Join(datadir, "smallcrosstx.db"), 768, 16, "eth/db/ela/")
	if err != nil {
		log.Error("smallcrosstx Open db", "err", err)
		return
	}
	smallCrossTxDb = db
	eventMux = evtMux
}

func OnSmallCrossTxMsg(signatures []string, rawTx string) {
	mulMsgPti.Lock()
	defer mulMsgPti.Unlock()

	if smallCrossTxMsgMap[rawTx] == true {
		return
	}

	arbiters, err := spv.GetArbiters()
	if err != nil {
		log.Error("get current arbiters failed", "error", err)
		return
	}
	for _, signature := range signatures {
		err := OnSmallCrossTx(arbiters, signature, rawTx)
		if err != nil {
			break
		}
	}
}

func OnSmallCrossTx(arbiters []string, signature string, rawTx string) error {
	if smallCrossTxMsgMap[rawTx] == true {
		return  ErrAllReadyConfirm
	}
	buff, err := hex.DecodeString(rawTx)
	if err != nil {
		return err
	}

	var txn elaType.Transaction
	err = txn.Deserialize(bytes.NewReader(buff))
	if err != nil {
		log.Error("[Small-Transfer] Decode transaction error", err.Error())
	}
	maxSignCount := GetMaxArbitersSign(len(arbiters))
	if GetArbiterSignCount(txn.Hash().String()) >= maxSignCount{
		return ErrAllReadyConfirm
	}
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return err
	}

	mulCountPti.Lock()
	defer mulCountPti.Unlock()
	count := smallCrossTxCountMap[txn.Hash().String()]
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
				PutSmallTxData(rawTx, txn.Hash().String())
			}
			count++
			smallCrossTxCountMap[txn.Hash().String()] = count
			if count <= maxSignCount {
				PutSmallTxSignature(signature, txn.Hash().String(), count-1)
				if count == maxSignCount {
					spv.NotifySmallCrossTx(txn)
					smallCrossTxMsgMap[rawTx] = true
					delete(verifiedArbiter, txn.Hash().String())
					tx := GetSmallCrossTxMsg(txn.Hash().String())
					eventMux.Post(core.SmallCrossTxEvent{RawTxID: tx.RawTxID, RawTx: tx.RawTx, Signatures: tx.Signatures})
				}
			}
			list := verifiedArbiter[txn.Hash().String()]
			verifiedArbiter[txn.Hash().String()] = append(list, pubkey)
			break
		}
	}
	return nil
}

func GetMaxArbitersSign(total int) int {
	return total * 2 / 3 + 1
}

func OnReceivedSmallCroTxFromDirectNet(signature string, rawTx string) {
	arbiters, err := spv.GetArbiters()
	if err != nil {
		log.Error("get current arbiters failed", "error", err)
		return
	}
	OnSmallCrossTx(arbiters, signature, rawTx)
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

func PutSmallTxData(rawTx string, elaHash string) {
	if smallCrossTxDb == nil {
		return
	}
	key := SmallTxDB_TX_PRE + elaHash
	smallCrossTxDb.Put([]byte(key), []byte(rawTx))
}

func PutSmallTxSignature(signature string, elaHash string, count int) {
	if smallCrossTxDb == nil {
		return
	}
	keyCount := SmallTxDB_SIGCOUNT_PRE + elaHash
	smallCrossTxDb.Put([]byte(keyCount), IntToBytes(int64(count)))

	num := strconv.Itoa(count)
	key := SmallTxDB_SIG_PRE + elaHash + num
	smallCrossTxDb.Put([]byte(key), []byte(signature))
}

func GetArbiterSignCount(elaHash string) int {
	keyCount := SmallTxDB_SIGCOUNT_PRE + elaHash
	data, err := smallCrossTxDb.Get([]byte(keyCount))
	if err != nil {
		log.Error("GetSmallCrossTxMsg count failed", "error", err)
		return 0
	}

	count := BytesToInt(data)
	return int(count)
}

func GetSmallCrossTxMsg(elaHash string) *SmallCrossTx {
	key := SmallTxDB_TX_PRE + elaHash
	rawTxData, err := smallCrossTxDb.Get([]byte(key))
	if err != nil {
		log.Error("GetSmallCrossTxMsg rawTx failed", "error", err)
		return nil
	}

	count := GetArbiterSignCount(elaHash)
	sigList := make([]string, 0)
	for i := 0; i <= count; i++ {
		num := strconv.Itoa(i)
		key = SmallTxDB_SIG_PRE + elaHash + num
		data, err := smallCrossTxDb.Get([]byte(key))
		if err != nil {
			log.Error("GetSmallCrossTxMsg signature failed", "error", err, "index", i, "count", count)
			return nil
		}
		sigList = append(sigList, string(data))
	}

	msg := SmallCrossTx{
		RawTxID:    elaHash,
		RawTx:      string(rawTxData),
		Signatures: sigList,
	}
	return &msg
}

func IntToBytes(n int64) []byte {
	buffer := bytes.NewBuffer([]byte{})
	binary.Write(buffer, binary.BigEndian, n)
	return buffer.Bytes()
}

func BytesToInt(b []byte) int64 {
	buffer := bytes.NewBuffer(b)
	var n int64
	binary.Read(buffer, binary.BigEndian, &n)
	return n
}
