package vm

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common/math"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/didjson"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"

	elacom "github.com/elastos/Elastos.ELA/common"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)

var (
	bankKey, _ = crypto.GenerateKey()
	bankAddr   = crypto.PubkeyToAddress(bankKey.PublicKey)

	userKey1, _ = crypto.GenerateKey()
	userAddr1   = crypto.PubkeyToAddress(userKey1.PublicKey)

	id1DocByts                      []byte
	id2DocByts                      []byte
	id11DocByts                     []byte
	idUser1DocByts                  []byte
	idUser2DocByts                  []byte
	customizedDIDDocSingleContrller []byte
	customizedDIDDocBytes1          []byte
	customizedDIDDocBytes2          []byte
	customizedVerifableCredDocBytes []byte

	DIDVerifableCredDocBytes []byte
	headerPayloadBytes        []byte
)

const (
	PayloadPrivateKey = "a38aa1f5f693a13ef0cf2f1c1c0155cbcdd9386f37b0000739f8cb50af601b7b"
)

func init() {
	id1DocByts, _ = LoadJsonData("./testdata/document.compact.json")

	id2DocByts, _ = LoadJsonData("./testdata/issuer.compact.json")

	id11DocByts, _ = LoadJsonData("./testdata/issuer.id.json")

	idUser1DocByts, _ = LoadJsonData("./testdata/user1.id.json")
	idUser2DocByts, _ = LoadJsonData("./testdata/user2.id.json")

	customizedDIDDocSingleContrller, _ = LoadJsonData("./testdata/examplecorp.id.json")
	customizedDIDDocBytes1, _ = LoadJsonData("./testdata/customized_did_single_sign.json")
	customizedDIDDocBytes2, _ = LoadJsonData("./testdata/foo.id.json")
	customizedVerifableCredDocBytes, _ = LoadJsonData("./testdata/customized_did_verifiable_credential.json")

	DIDVerifableCredDocBytes, _ = LoadJsonData("./testdata/did_verifiable_credential.json")
	headerPayloadBytes, _ = LoadJsonData("./testdata/customized_did_multi_controllers.json")
}

var didPayloadBytes = []byte(
	`{
        "id" : "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j",
        "publicKey":[{ "id": "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
                       "type":"ECDSAsecp256r1",
                       "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                       "publicKeyBase58":"zxt6NyoorFUFMXA8mDBULjnuH3v6iNdZm42PyG4c1YdC"
                      },
					{
					   "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master",
					   "type":"ECDSAsecp256r1",
					   "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
					   "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
				   }
                    ],
        "authentication":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                          {
                               "id": "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
                               "type":"ECDSAsecp256r1",
                               "controller":"did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN",
                               "publicKeyBase58":"zNxoZaZLdackZQNMas7sCkPRHZsJ3BtdjEvM2y5gNvKJ"
                           }
                         ],
        "authorization":["did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default"],
        "expires" : "2023-02-10T17:00:00Z"
	}`)

//right
var didPayloadInfoBytes = []byte(
	`{
		"header":{"operation":"create","specification":"elastos/did/1.0"},
		"payload":"eyJpZCI6ImRpZDplbGFzdG9zOmliRjdnTXo1c2FObzM5MlVkN3pTQVZSblFyc0E3cHgydEMiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiJyb1FHRWVNdU1LZjdFeUFWa3loZjdxSnN5cmtGVXBUZ296WEQ4VkpoS2hpQyJ9XSwiYXV0aGVudGljYXRpb24iOlsiI3ByaW1hcnkiXSwiZXhwaXJlcyI6IjIwMjQtMTEtMjVUMDI6MDA6MDBaIn0",
		"proof":{
			"signature":"nrbHEEysMLzBR1mMVRjan9yfQtNGmK6Rqy7v9rvUpsJNoIMsY5JtEUiJvW82jW4xNlvOOEDI-VpLK_GCgjoUdQ",
			"verificationMethod":"#primary"
			}
	 }
`)

var errDIDPayloadInfoBytes = []byte(
	`{
		"header":{"operation":"create","specification":"elastos/did/1.0"},
		"payload":"eyJpZCI6ImRpZDplbGFzdG9zOmlZUTZ1alBjd21UWmZqMmtOZmZXNEJDeXRKenlqbUpkRGQiLCJwdWJsaWNLZXkiOlt7ImlkIjoiI3ByaW1hcnkiLCJwdWJsaWNLZXlCYXNlNTgiOiJ6S1JYMWtOWGVYeTVuS3NyVTVtdVR3Z2Y3ZlhRYnhXZzdpUUtCdnBlS0dCUCJ9XSwiYXV0aGVudGljYXRpb24iOlsiI3ByaW1hcnkiXX0",
		"proof":{
			"signature":"nrbHEEysMLzBR1mMVRjan9yfQtNGmK6Rqy7v9rvUpsJNoIMsY5JtEUiJvW82jW4xNlvOOEDI-VpLK_GCgjoUdQ",
			"verificationMethod":"#primary"
			}
	 }
`)

func LoadJsonData(fileName string) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return []byte{}, err
	}
	return fileData, nil

}

func TestCheckDIDDIDPayload(t *testing.T) {
	//no create ------>update
	payloadUpdateDIDInfo := getPayloadUpdateDID()
	data, err := json.Marshal(payloadUpdateDIDInfo)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, nil)
	assert.EqualError(t, err, "DID WRONG OPERATION NOT EXIST")

	////doubale create
	payloadCreate := getPayloadCreateDID()
	data, err = json.Marshal(payloadCreate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, nil)
	assert.NoError(t, err)
}

func TestCommonDIDPayloadOperation(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	payloadCreate := getPayloadCreateDID()
	data, err := json.Marshal(payloadCreate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf := new(bytes.Buffer)
	payloadCreate.Serialize(buf, did.DIDVersion)
	receipt := getCreateDIDReceipt(*payloadCreate)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})
	rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 0)

	payloadUpdate := payloadCreate
	payloadUpdate.Header.Operation = did.Update_DID_Operation
	payloadUpdate.Header.PreviousTxid = common.Hash{}.String()
	payloadUpdate.Header.PreviousTxid = payloadUpdate.Header.PreviousTxid[2:]
	privateKey1, _ := elacom.HexStringToBytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, payloadUpdate.GetData())
	payloadUpdate.Proof.Signature = base64url.EncodeToString(sign)

	data, err = json.Marshal(payloadUpdate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	didWithPrefix := payloadUpdate.DIDDoc.ID
	verifDid := didWithPrefix + "#default"
	deactivePayLoad := getPayloadDeactivateDID(didWithPrefix, verifDid)
	data, err = json.Marshal(deactivePayLoad)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)
}

func getPayloadUpdateDID() *did.DIDPayload {
	info := new(did.DIDDoc)
	didjson.Unmarshal(didPayloadBytes, info)

	return &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "update",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: did.Proof{
			Type:               randomString(),
			VerificationMethod: randomString(),
			Signature:          randomString(),
		},
		DIDDoc: info,
	}
}

func randomString() string {
	a := make([]byte, 20)
	rand.Read(a)
	return elacom.BytesToHexString(a)
}

func TestIDChainStore_CreateDIDTx(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	doc := getPayloadCreateDID()
	var gas uint64 = 2000
	payloadJson, err := json.Marshal(doc)
	assert.NoError(t, err)
	err = checkDIDTransaction(payloadJson, nil)
	assert.NoError(t, err)

	info := new(did.DIDPayload)
	json.Unmarshal(didPayloadInfoBytes, info)
	payloadBase64, _ := base64url.DecodeString(info.Payload)
	payloadInfo := new(did.DIDDoc)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.DIDDoc = payloadInfo

	err = checkDIDTransaction(didPayloadInfoBytes, nil)
	assert.NoError(t, err)

	info.DIDDoc.Expires = "Mon Jan _2 15:04:05 2006"
	err = checkRegisterDID(evm, info, gas)
	assert.EqualError(t, err, "invalid Expires")

	info.DIDDoc.Expires = "2006-01-02T15:04:05Z07:00"
	err = checkRegisterDID(evm, info, gas)
	assert.EqualError(t, err, "invalid Expires")

	info.DIDDoc.Expires = "2018-06-30T12:00:00Z"
	err = checkRegisterDID(evm, info, gas)
	assert.NoError(t, err)

	info = new(did.DIDPayload)
	json.Unmarshal(errDIDPayloadInfoBytes, info)

	payloadBase64, _ = base64url.DecodeString(info.Payload)
	payloadInfo = new(did.DIDDoc)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.DIDDoc = payloadInfo

	err = checkRegisterDID(evm, info, gas)
	assert.EqualError(t, err, "invalid Expires")
}

func TestCheckRegisterDID(t *testing.T) {
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx2 := getPayloadDIDInfo(id2, "create", id2DocByts, privateKey2Str)
	tx1 := getPayloadDIDInfo(id1, "create", id1DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	receipt := getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})

	id := tx2.DIDDoc.ID
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id, did.Create_DID_Operation, buf.Bytes())
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 100, 123456)
	assert.NoError(t, err1)
	didParam.CustomIDFeeRate = 0

	docBytes, err := didjson.Marshal(tx2)
	assert.NoError(t, err)

	err2 := checkDIDTransaction(docBytes, statedb)
	assert.EqualError(t, err2, "DID WRONG OPERATION ALREADY EXIST")

	docBytes, err = didjson.Marshal(tx1)
	assert.NoError(t, err)
	err3 := checkDIDTransaction(docBytes, statedb)
	assert.NoError(t, err3)

}

func getPayloadDIDInfo(id string, didOperation string, docBytes []byte, privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didOperation,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary", //primary
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getPayloadCreateDID() *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "create",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
		},
		DIDDoc: info,
	}

	privateKey1, _ := elacom.HexStringToBytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func getCreateDIDReceipt(payload did.DIDPayload) *types.Receipt {
	id := payload.DIDDoc.ID
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	receipt := &types.Receipt{
		Status:            1,
		CumulativeGasUsed: 1,
		Logs: []*types.Log{},
		TxHash:          common.Hash{},

		DIDLog: types.DIDLog{
			DID: id,
			Operation: payload.Header.Operation,
			Data: buf.Bytes(),
		},
	}
	return receipt
}

func getDeactiveDIDReceipt(payload did.DIDPayload) *types.Receipt {
	id := payload.Payload
	payload.Payload =  base64url.EncodeToString([]byte(payload.Payload))
	buf := new(bytes.Buffer)
	payload.Serialize(buf, did.DIDVersion)
	receipt := &types.Receipt{
		Status:            1,
		CumulativeGasUsed: 1,
		Logs: []*types.Log{},
		TxHash:          common.Hash{},

		DIDLog: types.DIDLog{
			DID: id,
			Operation: payload.Header.Operation,
			Data: buf.Bytes(),
		},
	}
	return receipt
}

func TestIDChainStore_DeactivateDIDTx(t *testing.T) {
	didWithPrefix := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"
	verifDid := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default"
	id := didWithPrefix

	txCreateDID := getPayloadCreateDID()
	payload := getPayloadDeactivateDID(didWithPrefix, verifDid)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	receipt := getDeactiveDIDReceipt(*payload)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})
	//Deactive did  have no
	deactiveBytes, err := json.Marshal(payload)
	assert.NoError(t, err)
	err = checkDIDTransaction(deactiveBytes, nil)
	assert.EqualError(t, err, ErrNotFound.Error())

	buf := new(bytes.Buffer)
	txCreateDID.Serialize(buf, did.DIDVersion)
	receipt = getCreateDIDReceipt(*txCreateDID)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})
	statedb.AddDIDLog(id, did.Create_DID_Operation, buf.Bytes())
	err = rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 0)
	assert.NoError(t, err)

	err = checkDIDTransaction(deactiveBytes, statedb)
	assert.NoError(t, err)

	//wrong public key to verify sign
	verifDid = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master"
	payload = getPayloadDeactivateDID(didWithPrefix, verifDid)
	payloadbytes, err := json.Marshal(payload)
	assert.NoError(t, err)
	err = checkDIDTransaction(payloadbytes, statedb)
	assert.EqualError(t, err, "[VM] Check Sig FALSE")

	//deactive one deactivated did
	statedb.AddDIDLog(id, did.Deactivate_DID_Operation, buf.Bytes())
	rawdb.PersistDeactivateDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}))
	txDeactivateWrong := getPayloadDeactivateDID(didWithPrefix, verifDid)
	deactiveBytes, _ = json.Marshal(txDeactivateWrong)
	err = checkDIDTransaction(deactiveBytes, statedb)
	assert.EqualError(t, err, "DID WAS AREADY DEACTIVE")

}

func getPayloadDeactivateDID(id, verifDid string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     did.Deactivate_DID_Operation,
		},
		Payload: id,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifDid,
		},
	}
	privateKey1 := common.Hex2Bytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func TestCustomizedDID(t *testing.T) {
	id1 := "did:elastos:imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj"
	privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ" //413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ
	tx1 := getPayloadDIDInfo(id1, "create", id11DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)


	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 100)
	assert.NoError(t, err1)

	//examplercorp.id.json
	didParam.IsTest = true
	tx3 := getCustomizedDIDDoc(id1, "create", customizedDIDDocSingleContrller, privateKey1Str)

	receipt := getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})

	didParam.CustomIDFeeRate = 0
	err3 := checkCustomizedDID(evm, tx3, 20000)
	assert.NoError(t, err3)

	// todo fix me

	didParam.IsTest = false
}

//issuer.json SelfProclaimedCredential
func TestCustomizedDIDMultSign(t *testing.T) {
	didParam.IsTest = true
	defer func() {
		didParam.IsTest = false
	}()
	idUser1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	tx1 := getPayloadDIDInfo(idUser1, "create", idUser1DocByts, privateKeyUser1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})

	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 100, 123456)
	assert.NoError(t, err1)

	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	idUser2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	tx2 := getPayloadDIDInfo(idUser2, "create", idUser2DocByts, privateKeyUser2Str)

	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.Prepare(common.HexToHash("0x1234"), common.HexToHash("0x1234"), 1)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.HexToHash("0x1234"), 0, types.Receipts{receipt})

	err2 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.HexToHash("0x1234")), 100, 123456)
	assert.NoError(t, err2)

	CustomizedDIDTx2 := getCustomizedDIDDocMultiSign(idUser1, idUser2, "create", customizedDIDDocBytes2,
		privateKeyUser1Str, privateKeyUser2Str)
	didParam.CustomIDFeeRate = 0
	err := checkCustomizedDID(evm, CustomizedDIDTx2, 20000)
	assert.NoError(t, err)
	// todo fix me
}

func getCustomizedDIDDocMultiSign(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	//var Proofs []*types.Proof
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		DIDDoc:  info,
	}
	proof1 := &did.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: id1 + "#primary", //"did:elastos:" +
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	p.Proof = *proof1
	return p
}

func getCustomizedDIDDoc(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: id + "#primary", //"did:elastos:" +
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//didDIDPayload must be create or update
func getCustomizedDIDVerifiableCredentialTx(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	fmt.Println(" ---docBytes--- ", string(docBytes))
	info := new(did.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		CredentialDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

//todo complete the test
//self verifiable credential
func Test0DIDVerifiableCredentialTx(t *testing.T) {
	//id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	//privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	//tx1 := getDIDTx(id1, "create", id1DocByts, privateKey1Str)
	//
	//batch := s.validator.Store.NewBatch()
	//err1 := s.validator.Store.PersistRegisterDIDTx(batch, []byte("iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"), tx1,
	//	100, 123456)
	//s.NoError(err1)
	//batch.Commit()
	//
	//CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	//err1 = s.validator.checkCustomizedDID(CustomizedDIDTx1)
	//s.NoError(err1)

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", id2DocByts, privateKey2Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})
	err2 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 0)
	assert.NoError(t, err2)
	//did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB
	//
	verifableCredentialTx := getCustomizedDIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		DIDVerifableCredDocBytes, privateKey2Str)

	jsonData, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(jsonData, statedb)
	assert.NoError(t, err)
}

// one cotroller
func TestCustomizedDIDVerifiableCredentialTx(t *testing.T) {
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", id1DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err1)

	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getPayloadDIDInfo(id2, "create", id2DocByts, privateKey2Str)

	statedb2, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb2.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	err2 := rawdb.PersistRegisterDIDTx(statedb2.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb2.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err2)

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	statedb3, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb3.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	err3 := rawdb.PersistRegisterDIDTx(statedb3.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb3.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err3)

	//verifableCredentialTx := getCustomizedDIDVerifiableCredentialTx("iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
	//	"declare", customizedVerifableCredDocBytes, privateKey1Str)


	//err := checkVerifiableCredential(evm, verifableCredentialTx)
	//assert.NoError(t, err)

	//credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	//statedb4, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//err4 := rawdb.PersistVerifiableCredentialTx(statedb3.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), []byte(credentialID), verifableCredentialTx,
	//	100, 123456)
	//s.NoError(err4)
	//batch4.Commit()

	//txDeactivate := getDeactivateCustomizedDIDTx(credentialID, id2, privateKey2Str)
	////Deactive did  have no
	//err5 := s.validator.checkCustomizedDIDDeactivateTX(txDeactivate)
	//s.NoError(err5)
	////////////////////////////
	//verifableCredentialRevokeTx := getCustomizedDIDVerifiableCredentialTx("iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
	//	"revoke", customizedVerifableCredDocBytes, privateKey2Str)
	//err5 := s.validator.checkVerifiableCredential(verifableCredentialRevokeTx)
	//s.NoError(err5)
	////////////////////////////////
}

func getCustomizedDIDTx(id string, didDIDPayload string, docBytes []byte,
	privateKeyStr string) *did.DIDPayload {
	//pBytes := getDIDPayloadBytes(id)
	info := new(did.DIDDoc)
	json.Unmarshal(docBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload: base64url.EncodeToString(docBytes),
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}

func TestDeactivateCustomizedDIDTX(t *testing.T) {
	//id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"

	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", id1DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})

	err := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err)

	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getPayloadDIDInfo(id2, "create", id2DocByts, privateKey2Str)
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)

	statedb.Prepare(common.HexToHash("0x1234"), common.HexToHash("0x1234"), 1)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.HexToHash("0x1234"), 0, types.Receipts{receipt})
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())

	err2 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.HexToHash("0x1234")), 0, 100)
	assert.NoError(t, err2)

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", customizedDIDDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	//batch3 := s.validator.Store.NewBatch()
	//err3 := s.validator.Store.PersistRegisterDIDTx(batch3, []byte(customizedDID), CustomizedDIDTx1,
	//	101, 123456)
	statedb.Prepare(common.HexToHash("0x5678"), common.HexToHash("0x5678"), 1)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.HexToHash("0x5678"), 0, types.Receipts{receipt})
	err3 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.HexToHash("0x5678")),0, 0)
	assert.NoError(t, err3)
	/////////////////////////
	//customizedDID
	//id1 is verificationmethod did
	//privateKey1Str outter proof sign(not for doc sign)
	txDeactivate := getDeactivateCustomizedDIDTx(customizedDID, id1, privateKey1Str)
	//Deactive did  have no
	data, err := json.Marshal(txDeactivate)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf = new(bytes.Buffer)
	txDeactivate.Serialize(buf, did.DIDVersion)
	statedb.Prepare(common.HexToHash("0x2345"), common.HexToHash("0x2345"), 1)
	statedb.AddDIDLog(customizedDID, did.Deactivate_DID_Operation, buf.Bytes())
	receipt = getDeactiveDIDReceipt(*txDeactivate)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.HexToHash("0x2345"), 0, types.Receipts{receipt})
	err4 := rawdb.PersistDeactivateDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.HexToHash("0x2345")))
	assert.NoError(t, err4)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "DID WAS AREADY DEACTIVE")
}

//didDIDPayload must be create or update
func getDeactivateCustomizedDIDTx(customizedDID, verifiacationDID, privateKeyStr string) *did.DIDPayload {
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     did.Deactivate_DID_Operation,
		},
		Payload: customizedDID,
		Proof: did.Proof{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: verifiacationDID + "#primary", //"did:elastos:" +
		},
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)

	publickey := base58.Decode("2BhWFosWHCKtBQpsPD3QZUY4NwCzavKdZEh6HfQDhciAY")
	pubkey, err := elaCrypto.DecodePoint(publickey)
	fmt.Println(err)
	err = elaCrypto.Verify(*pubkey, p.GetData(), sign)
	fmt.Println(err)
	return p
}

func TestHeaderPayloadDIDTX(t *testing.T) {
	didParam.CustomIDFeeRate = 0
	err := checkDIDTransaction(headerPayloadBytes, nil)
	assert.NoError(t, err)
}

func checkDIDTransaction(didpayload []byte, db *state.StateDB) error {
	preData := common.Hash{}
	didpayload = append( preData.Bytes(), didpayload...)

	did_contract := new(operationDID)
	statedb := db
	if statedb == nil {
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	}

	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	evm.GasPrice = big.NewInt(int64(params.DIDBaseGasprice))
	gas := did_contract.RequiredGas(evm, []byte(didpayload))
	if gas == math.MaxUint64 {
		return errors.New("RequiredGas is 0")
	}
	result, err := did_contract.Run(evm, []byte(didpayload), gas)
	if err != nil {
		return err
	}
	val := common.BytesToHash(result)
	if val.Big().Uint64() != 1 {
		return errors.New("result error")
	}
	return nil
}