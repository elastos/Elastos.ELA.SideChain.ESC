package pledgeBill

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb/leveldb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/smallcrosstx"

	elaCom "github.com/elastos/Elastos.ELA/common"
	it "github.com/elastos/Elastos.ELA/core/types/interfaces"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

const (
	pledgeTxPreKey     = "elaPledgeTx_"
	pledgeTxVersionKey = "ela_PledgeTx_Version_"
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

func getTxKey(key string) string {
	return pledgeTxPreKey + key
}

func getTxVersionKey(key string) string {
	return pledgeTxVersionKey + key
}

func ProcessPledgedBill(elaTx it.Transaction) {
	payloadVersion := elaTx.PayloadVersion()
	payLoadData := elaTx.Payload().Data(payloadVersion)
	var createNft payload.CreateNFT
	var reader = bytes.NewReader(payLoadData)
	err := createNft.Deserialize(reader, payloadVersion)
	if err != nil {
		log.Error("ProcessPledgedBill failed", "deserialize error", err, "elaTx.PayloadVersion()", elaTx.PayloadVersion())
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
		return
	}

	versionKey := getTxVersionKey(elaTx.Hash().String())
	err = putTxPayLoadVersion(versionKey, payloadVersion)
	if err != nil {
		log.Error("putTxPayLoadVersion failed", "save data error", err.Error())
	}
}

func GetPledgeBillData(txHash string) (sAddress string, tokenID *big.Int, err error) {
	if txHash[0:2] == "0x" {
		txHash = txHash[2:]
	}
	p, _, err := GetCreateNFTPayload(txHash)
	if err != nil {
		return sAddress, tokenID, err
	}
	sAddress = p.StakeAddress
	elaHash, err := elaCom.Uint256FromHexString(txHash)
	if err != nil {
		return p.StakeAddress, tokenID, err
	}
	nftID := elaCom.GetNFTID(p.ReferKey, *elaHash)
	tokenID = big.NewInt(0).SetBytes(nftID.Bytes())
	return sAddress, tokenID, nil
}

func GetBPosNftPayloadVersion(txHash string) (payloadVersion byte, err error) {
	if txHash[0:2] == "0x" {
		txHash = txHash[2:]
	}
	versionKey := getTxVersionKey(txHash)
	payloadVersion, err = getPayloadVerion(versionKey)
	return payloadVersion, err
}

func GetCreateNFTPayload(txHash string) (p *payload.CreateNFT, payloadVersion byte, err error) {
	if txHash[0:2] == "0x" {
		txHash = txHash[2:]
	}
	payloadVersion, _ = GetBPosNftPayloadVersion(txHash)
	key := getTxKey(txHash)
	v, err := getData(key)
	if err != nil {
		return nil, 0, errors.New("GetCreateNFTPayload getData error" + err.Error() + "hash " + txHash)
	}
	nr := bytes.NewReader([]byte(v))
	p = new(payload.CreateNFT)
	err = p.Deserialize(nr, payloadVersion)
	return p, payloadVersion, err
}

func putTxPayLoadVersion(key string, version byte) error {
	data := make([]byte, 1)
	data[0] = version
	return putData(key, data)
}

func getPayloadVerion(key string) (byte, error) {
	transactionDBMutex.Lock()
	defer transactionDBMutex.Unlock()
	value, err := spvTransactiondb.Get([]byte(key))
	if err != nil {
		return 0, err
	}
	return value[0], nil
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
