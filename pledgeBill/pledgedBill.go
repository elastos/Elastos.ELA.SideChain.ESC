package pledgeBill

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"math/big"
	"sync"
	"sync/atomic"
	"time"

	elaCom "github.com/elastos/Elastos.ELA/common"
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"

	ethereum "github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/blocksigner"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb/leveldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/smallcrosstx"
)

const (
	pledgeTxPreKey      = "elaPledgeTx_"
	pledgeTxIndexKey    = "ela_PledgeTx_Index_Key"
	pledgeTxIndexPreKey = "ela_PledgeTx_Index_PreKey"
	pledgeTxSeekIndex   = "ela-PledgeTx_Seek_Index"
)

var (
	pledgeBillContract string
	isOnDuty           int32
	isSeeking          int32
	transactionDBMutex *sync.RWMutex
	spvTransactiondb   *leveldb.Database
	signerAddress      common.Address

	escClient *ethclient.Client
)

func Init(spvDb *leveldb.Database, dbMutex *sync.RWMutex, contractAddress string, signer common.Address, ipcClient *ethclient.Client) {
	spvTransactiondb = spvDb
	transactionDBMutex = dbMutex
	pledgeBillContract = contractAddress
	signerAddress = signer
	escClient = ipcClient
}

func OnDuty() {
	if atomic.LoadInt32(&isOnDuty) == 1 {
		return
	}
	atomic.StoreInt32(&isOnDuty, 1)
	go seekAndMintPledgeBill()
	select {
	case <-time.After(5 * time.Second):
		atomic.StoreInt32(&isOnDuty, 0)
		return
	}
}

func getTxKey(key string) string {
	return pledgeTxPreKey + key
}

func getTxIndexKey(index uint64) string {
	return pledgeTxIndexPreKey + string(EncodeUnTransactionNumber(index))
}

func ProcessPledgedBill(elaTx it.Transaction) {
	payLoadData := elaTx.Payload().Data(elaTx.PayloadVersion())
	var createNft payload.CreateNFT
	var reader = bytes.NewReader(payLoadData)
	err := createNft.Deserialize(reader, 0)
	if err != nil {
		log.Error("ProcessPledgedBill failed", "deserialize error", err)
		return
	}
	nftID := elaCom.GetNFTID(createNft.ReferKey, elaTx.Hash())
	log.Info("Get CreateNFT tx", "ReferKey", createNft.ReferKey.String(), "nftIDHexString", nftID.String(), "tokenID", big.NewInt(0).SetBytes(nftID.Bytes()).String())
	genesis, err := escClient.BlockByNumber(context.Background(), big.NewInt(0))
	if err != nil {
		log.Error("ProcessPledgedBill failed", "get genesis block error", err)
		return
	}
	if createNft.GenesisBlockHash.String() != genesis.GetHash().String() {
		log.Error("error genesis", "spv.GenesisHash", genesis.GetHash().String(), "createNFT SideChain", createNft.GenesisBlockHash.String())
		return
	}
	key := getTxKey(elaTx.Hash().String())
	v, err := getData(key)
	if err != nil && err.Error() != smallcrosstx.ErrNotFound {
		log.Error("ProcessPledgedBill failed", "error", err)
		return
	}
	if err == nil && v != "" {
		log.Error("ProcessPledgedBill failed, already save this transaction", "tx.hash", elaTx.Hash().String())
		return
	}

	err = putData(key, payLoadData)
	if err != nil {
		log.Error("ProcessPledgedBill failed", "save data error", err.Error())
	}

	//txIndex, err := GetIndexByKey(pledgeTxIndexKey)
	//if err != nil {
	//	log.Error("ProcessPledgedBill GetIndexByKey failed", "error", err)
	//	return
	//}
	//txIndex++
	//key = getTxIndexKey(txIndex)
	//putData(key, []byte(elaTx.Hash().String()))
	//putData(pledgeTxIndexKey, EncodeUnTransactionNumber(txIndex))

	//if atomic.LoadInt32(&isOnDuty) == 1 && atomic.LoadInt32(&isSeeking) == 0 {
	//	go seekAndMintPledgeBill()
	//}
}

func seekAndMintPledgeBill() {
	if atomic.LoadInt32(&isSeeking) == 1 {
		return
	}
	atomic.StoreInt32(&isSeeking, 1)
	defer func() {
		atomic.StoreInt32(&isSeeking, 0)
	}()
	if !blocksigner.SelfIsProducer {
		log.Error("error signers", "signer", signerAddress.String())
		return
	}
	for {
		if atomic.LoadInt32(&isOnDuty) == 0 {
			log.Info("stop seekAndMintPledgeBill is not onDuty")
			return
		}
		seekIndex, err := GetIndexByKey(pledgeTxSeekIndex)
		if err != nil {
			log.Error("seekAndMintPledgeBill GetIndexByKey failed", "error", err, "key", pledgeTxSeekIndex)
			return
		}
		txIndex, err := GetIndexByKey(pledgeTxIndexKey)
		if err != nil {
			log.Error("seekAndMintPledgeBill GetIndexByKey failed", "error", err, "key", pledgeTxIndexKey)
			return
		}
		if seekIndex >= txIndex {
			log.Info("seek over pledgeBill tx", "seekIndex", seekIndex, "index", txIndex)
		}
		//key := getTxIndexKey(seekIndex)
		//txHash, err := getData(key)
		//if err != nil {
		//	log.Error("seekAndMintPledgeBill get elaTx failed", "error", err, "seekIndex", seekIndex)
		//	return
		//}

		//err = MintPledgeBill(txHash)
		//if err != nil {
		//	log.Error("MintPledgeBill failed", "error", err)
		//}
	}
}

func GetPledgeBillData(txHash string) (sAddress string, tokenID *big.Int, err error) {
	if txHash[0:2] == "0x" {
		txHash = txHash[2:]
	}

	key := getTxKey(txHash)
	v, err := getData(key)
	if err != nil {
		return sAddress, tokenID, errors.New("callPledgeBillContract getData error" + err.Error())
	}

	nr := bytes.NewReader([]byte(v))
	p := new(payload.CreateNFT)
	p.Deserialize(nr, 1)

	sAddress = p.StakeAddress
	elaHash, err := elaCom.Uint256FromHexString(txHash)
	if err != nil {
		return p.StakeAddress, tokenID, err
	}
	nftID := elaCom.GetNFTID(p.ReferKey, *elaHash)
	tokenID = big.NewInt(0).SetBytes(nftID.Bytes())
	return sAddress, tokenID, nil
}

func putData(key string, value []byte) error {
	transactionDBMutex.Lock()
	defer transactionDBMutex.Unlock()
	return spvTransactiondb.Put([]byte(key), value)
}

func getData(key string) (string, error) {
	transactionDBMutex.Lock()
	defer transactionDBMutex.Unlock()
	value, err := spvTransactiondb.Get([]byte(key))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

//func MintPledgeBill(elaHash string) error {
//	toAddress, tokenID, err := GetPledgeBillData(elaHash)
//	if err != nil {
//		return err
//	}
//	a, err := GetMintTickFunABI()
//	if err != nil {
//		return err
//	}
//	isMinted, err := IsMintByTokenID(tokenID)
//	if err != nil {
//		return err
//	}
//	if isMinted {
//		return errors.New("already mint this token" + tokenID.String())
//	}
//	hash := common.HexToHash(elaHash)
//	data, err := a.Pack("mintTick", toAddress, tokenID, hash)
//	if err != nil {
//		return err
//	}
//	hash, err = makeAndSendContractTransaction(data)
//	if err != nil {
//		log.Error("MintPledgeBill failed", "error", err)
//	}
//	return err
//}

func IsMintByTokenID(tokenID *big.Int) (bool, error) {
	a, err := GetTickFromTokenIdABI()
	if err != nil {
		return false, err
	}
	data, err := a.Pack("getTickFromTokenId", tokenID)
	if err != nil {
		return false, err
	}
	toAddress := common.HexToAddress(pledgeBillContract)
	msg := ethereum.CallMsg{From: signerAddress, To: &toAddress, Data: data}

	out, err := escClient.CallContract(context.TODO(), msg, nil)
	if err != nil {
		return false, err
	}
	fmt.Println(out)
	return false, nil
}

func makeAndSendContractTransaction(data []byte) (common.Hash, error) {
	var hash common.Hash
	toAddress := common.HexToAddress(pledgeBillContract)
	msg := ethereum.CallMsg{From: signerAddress, To: &toAddress, Data: data}
	gasLimit, err := escClient.EstimateGas(context.Background(), msg)
	if err != nil {
		log.Error("EstimateGas err:", "error", err)
		return hash, err
	}
	if gasLimit == 0 {
		return hash, errors.New("EstimateGasLimit is 0")
	}

	//price := new(big.Int).Quo(fee, new(big.Int).SetUint64(gasLimit))
	callmsg := ethereum.TXMsg{From: signerAddress, To: &toAddress, Data: data}
	hash, err = escClient.SendPublicTransaction(context.Background(), callmsg)
	return hash, err
}
