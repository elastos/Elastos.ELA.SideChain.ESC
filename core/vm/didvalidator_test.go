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
	customizedDIDDocBytes2          []byte

	headerPayloadBytes        []byte
	issuerDocByts             []byte
	docDocBytes 			  []byte
	custIDSingleSignDocBytes1 []byte
	custIDVerifCredDocBytes   []byte
	didVerifCred      		  []byte
	user1IDDocByts   	      []byte
	user2IDDocByts            []byte
	fooIDDocBytes             []byte
	custIDVerifyCredContrl    []byte
)

const (
	PayloadPrivateKey = "a38aa1f5f693a13ef0cf2f1c1c0155cbcdd9386f37b0000739f8cb50af601b7b"
)

func init() {
	id11DocByts, _ = LoadJsonData("./testdata/issuer.id.json")

	user1IDDocByts, _ = LoadJsonData("./testdata/user1.id.json")
	user2IDDocByts, _ = LoadJsonData("./testdata/user2.id.json")

	customizedDIDDocSingleContrller, _ = LoadJsonData("./testdata/examplecorp.id.json")
	custIDSingleSignDocBytes1, _ = LoadJsonData("./testdata/customized_did_single_sign.json")
	customizedDIDDocBytes2, _ = LoadJsonData("./testdata/foo.id.json")
	custIDVerifCredDocBytes, _ = LoadJsonData("./testdata/customized_did_verifiable_credential.json")

	headerPayloadBytes, _ = LoadJsonData("./testdata/customized_did_multi_controllers.json")
	issuerDocByts, _ = LoadJsonData("./testdata/issuer.json")
	docDocBytes, _ = LoadJsonData("./testdata/document.json")
	didVerifCred, _ = LoadJsonData("./testdata/did_verifiable_credential.json")
	fooIDDocBytes, _ = LoadJsonData("./testdata/foo.id.json")
	custIDVerifyCredContrl, _ = LoadJsonData("./testdata/customized_did_verifiable_credential_controllers.json")

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

	data, err := json.Marshal(info)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "invalid Expires")
}

func TestCheckRegisterDID(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

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
			VerificationMethod: id + "#primary", //"did:elastos:" +
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
			VerificationMethod: "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default",
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

func getDeclareDIDReceipt(payload did.DIDPayload) *types.Receipt {
	id := payload.CredentialDoc.ID
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

//issuer.json SelfProclaimedCredential
func TestSelfProclaimedCredential(t *testing.T) {
	privateKey3Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id3 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"

    didParam.CustomIDFeeRate = 0
	//id3DocBytes
	tx3 := getPayloadDIDInfo(id3, "create", issuerDocByts, privateKey3Str)
	data, err := json.Marshal(tx3)
	assert.NoError(t, err)
	err3 := checkDIDTransaction(data, nil)
	assert.NoError(t, err3)

	tx3_2 := getPayloadDIDInfo(id3, "create", issuerDocByts, privateKey3Str)
	data, err = json.Marshal(tx3_2)
	assert.NoError(t, err)
	err3_2 := checkDIDTransaction(data, nil)
	assert.NoError(t, err3_2)
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
	tx1 := getPayloadDIDInfo(idUser1, "create", user1IDDocByts, privateKeyUser1Str)

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
	tx2 := getPayloadDIDInfo(idUser2, "create", user2IDDocByts, privateKeyUser2Str)

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
func getIDVerifiableCredentialTx(id string, didDIDPayload string, docBytes []byte,
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
			VerificationMethod: id + "#primary",
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
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

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
	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		didVerifCred, privateKey2Str)

	jsonData, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(jsonData, statedb)
	assert.NoError(t, err)
}

//self verifiable credential
func TestRevokeVerifiableCredentialTx(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt})
	err2 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err2)

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB",
		"declare",
		didVerifCred, privateKey2Str)
	fmt.Println(verifableCredentialTx)
	err := checkVerifiableCredential(evm, verifableCredentialTx)
	assert.NoError(t, err)

}

// one cotroller
func TestRevokeCustomizedDIDVerifiableCredentialTx(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt := getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.Hash{}, 0, types.Receipts{receipt})
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}),
		100, 123456)
	assert.NoError(t, err1)

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)

	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	tx2hash := common.HexToHash("0x1234")
	statedb.Prepare(tx2hash, tx2hash, 1)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx2hash, 0, types.Receipts{receipt})
	err2 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(tx2hash),
		100, 123456)
	assert.NoError(t, err2)


	tx3hash := common.HexToHash("0x2345")
	statedb.Prepare(tx3hash, tx3hash, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx3hash, 0, types.Receipts{receipt})

	err3 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(tx3hash),
		100, 123456)
	assert.NoError(t, err3)

	verifableCredentialTx := getIDVerifiableCredentialTx(id1, "declare", custIDVerifCredDocBytes, privateKey1Str)
	data, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)


	tx4Hash := common.HexToHash("0x3456")
	credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	buf = new(bytes.Buffer)
	statedb.Prepare(tx4Hash, tx4Hash, 1)
	verifableCredentialTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(credentialID, did.Declare_Verifiable_Credential_Operation, buf.Bytes())
	receipt = getDeclareDIDReceipt(*verifableCredentialTx)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), tx4Hash, 0, types.Receipts{receipt})
	err4 := rawdb.PersistVerifiableCredentialTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(tx4Hash), 100, 123456, tx4Hash)
	assert.NoError(t, err4)

	//iWFAUYhTa35c1fPe3iCJvihZHx6quumnym
	//the issuer revoke the credential
	verifableCredentialRevokeTx := getIDVerifiableCredentialTx(id2, "revoke", custIDVerifCredDocBytes,
		privateKey2Str)
	data, err5 := json.Marshal(verifableCredentialRevokeTx)
	assert.NoError(t, err5)
	err5 = checkDIDTransaction(data, statedb)
	assert.NoError(t, err5)
}

// declare after real revoke
func TestRevokeBeforeRegisterVerifiableCredentialTx(t *testing.T) {
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	//iWFAUYhTa35c1fPe3iCJvihZHx6quumnym
	//ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB issuer this credential and customizedDID := "did:elastos:foobar" is the owner
	//"did:elastos:foobar" have only one controller is id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	verifableCredentialRevokeTx := getIDVerifiableCredentialTx(id2, "revoke", custIDVerifCredDocBytes,
		privateKey2Str)
	err := checkVerifiableCredential(evm, verifableCredentialRevokeTx)
	assert.NoError(t, err)

	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	credentialID := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile"
	hash := common.Hash{}
	buf := new(bytes.Buffer)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(credentialID, did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt := getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt})
	err = rawdb.PersistVerifiableCredentialTx(db, statedb.GetDIDLog(hash), 0, 0, hash)
	assert.NoError(t, err)

	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
	buf = new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt})
	err1 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash1), 0, 0)
	assert.NoError(t, err1)

	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt})
	err2 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash2), 100, 123456)
	assert.NoError(t, err2)

	hash3 := common.HexToHash("3456")
	statedb.Prepare(hash3, hash3, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"

	buf = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1)
	rawdb.WriteReceipts(db, hash3, 0, types.Receipts{receipt})
	err3 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash3), 101, 123456)
	assert.NoError(t, err3)
	////iWFAUYhTa35c1fPe3iCJvihZHx6quumnym is the owner controller of thie credential
	verifableCredentialTx := getIDVerifiableCredentialTx(id1, "declare", custIDVerifCredDocBytes,
		privateKey1Str)
	data, err := json.Marshal(verifableCredentialTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "VerifiableCredential WRONG OPERATION ALREADY Revoked")
}


// declare after wrong revoke
func TestWrongRevokeBeforeRegisterVerifiableCredentialTx(t *testing.T) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y",
		"revoke", custIDVerifCredDocBytes, privateKey1Str)
	err5 := checkVerifiableCredential(evm, verifableCredentialRevokeTx)
	assert.NoError(t, err5)

	hash := common.Hash{}
	buff := new(bytes.Buffer)
	verifableCredentialRevokeTx.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buff.Bytes())
	receipt := getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt})
	err := rawdb.PersistVerifiableCredentialTx(db, statedb.GetDIDLog(hash),
		100, 123456, hash)
	assert.NoError(t, err)

	hash1 := common.HexToHash("0x1234")
	statedb.Prepare(hash1, hash1, 1)
	id1 := "iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey2Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)
	buff = new(bytes.Buffer)
	tx1.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym", did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*tx1)
	rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt})
	err1 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash1),
		100, 123456)
	assert.NoError(t, err1)

	hash2 := common.HexToHash("0x2345")
	statedb.Prepare(hash2, hash2, 1)
	id2 := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buff = new(bytes.Buffer)
	tx2.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB", did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt})
	err2 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash2),
		100, 123456)
	assert.NoError(t, err2)

	hash3 := common.HexToHash("0x3456")
	statedb.Prepare(hash3, hash3, 1)
	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
	customizedDID := "did:elastos:foobar"
	buff = new(bytes.Buffer)
	CustomizedDIDTx1.Serialize(buff, did.DIDVersion)
	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buff.Bytes())
	receipt = getCreateDIDReceipt(*CustomizedDIDTx1)
	rawdb.WriteReceipts(db, hash3, 0, types.Receipts{receipt})
	err3 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash3),
		101, 123456)
	assert.NoError(t, err3)

	verifableCredentialTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"declare", custIDVerifCredDocBytes, privateKey1Str)
	err = checkVerifiableCredential(evm, verifableCredentialTx)
	assert.NoError(t, err)
}

// revoke again
func TestDuplicatedRevokeVerifiableCredentialTx(t *testing.T) {
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
	//evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	verifableCredentialRevokeTx := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", custIDVerifCredDocBytes, privateKey2Str)
	data, err := json.Marshal(verifableCredentialRevokeTx)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.NoError(t, err)

	buf := new(bytes.Buffer)
	verifableCredentialRevokeTx.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog("did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB#profile", did.Revoke_Verifiable_Credential_Operation, buf.Bytes())
	receipt := getDeclareDIDReceipt(*verifableCredentialRevokeTx)
	rawdb.WriteReceipts(db, common.Hash{}, 0, types.Receipts{receipt})

	err = rawdb.PersistVerifiableCredentialTx(db, statedb.GetDIDLog(common.Hash{}), 0, 100, common.Hash{})
	assert.NoError(t, err)

	verifableCredentialRevokeTx2 := getIDVerifiableCredentialTx("did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym",
		"revoke", custIDVerifCredDocBytes, privateKey2Str)
	data, err = json.Marshal(verifableCredentialRevokeTx2)
	assert.NoError(t, err)
	err = checkDIDTransaction(data, statedb)
	assert.EqualError(t, err, "VerifiableCredential revoked again")
}

//more than  one cotroller
//func TestCustomizedDIDVerifiableCredentialTx2(t *testing.T) {
//	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
//	db := statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore)
//	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
//
//	hash := common.Hash{}
//	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
//	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"
//	tx0 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
//	buff := new(bytes.Buffer)
//	tx0.Serialize(buff, did.DIDVersion)
//	statedb.AddDIDLog(id2, did.Create_DID_Operation, buff.Bytes())
//	receipt := getCreateDIDReceipt(*tx0)
//	rawdb.WriteReceipts(db, hash, 0, types.Receipts{receipt})
//	err0 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash),
//		100, 123456)
//	assert.NoError(t, err0)
//
//	hash1 := common.HexToHash("0x1234")
//	statedb.Prepare(hash1, hash1, 1)
//	idUser1 := "did:elastos:iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
//	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
//	tx1 := getPayloadDIDInfo(idUser1, "create", user1IDDocByts, privateKeyUser1Str)
//	buff = new(bytes.Buffer)
//	tx1.Serialize(buff, did.DIDVersion)
//	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buff.Bytes())
//	receipt = getCreateDIDReceipt(*tx1)
//	rawdb.WriteReceipts(db, hash1, 0, types.Receipts{receipt})
//	err1 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash1),
//		100, 123456)
//	assert.NoError(t, err1)
//
//	hash2 := common.HexToHash("0x2345")
//	statedb.Prepare(hash2, hash2, 1)
//	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
//	idUser2 := "did:elastos:idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
//	tx2 := getPayloadDIDInfo(idUser2, "create", user2IDDocByts, privateKeyUser2Str)
//	buff = new(bytes.Buffer)
//	tx2.Serialize(buff, did.DIDVersion)
//	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buff.Bytes())
//	receipt = getCreateDIDReceipt(*tx2)
//	rawdb.WriteReceipts(db, hash2, 0, types.Receipts{receipt})
//	err2 := rawdb.PersistRegisterDIDTx(db, statedb.GetDIDLog(hash2),
//		100, 123456)
//	assert.NoError(t, err2)
//
//	hash3 := common.HexToHash("0x3456")
//	statedb.Prepare(hash3, hash3, 1)
//	CustomizedDIDTx1 := getCustomizedDIDDocMultiSign(idUser1, idUser2, "create", fooIDDocBytes,
//		privateKeyUser1Str, privateKeyUser2Str)
//	customizedDID := "did:elastos:foobar"
//	buff = new(bytes.Buffer)
//	CustomizedDIDTx1.Serialize(buff, did.DIDVersion)
//	statedb.AddDIDLog(customizedDID, did.Create_DID_Operation, buff.Bytes())
//	receipt = getCreateDIDReceipt(*CustomizedDIDTx1)
//	receipt.DIDLog.DID = customizedDID
//	rawdb.WriteReceipts(db, hash3, 0, types.Receipts{receipt})
//	err3 := rawdb.PersistRegisterDIDTx(db,
//		statedb.GetDIDLog(hash3),
//		101, 123456)
//	assert.NoError(t, err3)
//
//	verifableCredentialTx := getCustomizedDIDVerifiableCredPayloadContollers(idUser1, idUser2, "declare",
//		custIDVerifyCredContrl, privateKeyUser1Str, privateKeyUser2Str)
//	err := checkVerifiableCredential(evm, verifableCredentialTx)
//	assert.NoError(t, err)
//}

// more than one controllers
func getCustomizedDIDVerifiableCredPayloadContollers(id1, id2 string, didDIDPayload string, docBytes []byte,
	privateKeyStr1, privateKeyStr2 string) *did.DIDPayload {
	info := new(did.VerifiableCredentialDoc)
	json.Unmarshal(docBytes, info)
	fmt.Println("getCustomizedDIDDocMultiSign " + string(docBytes))

	//var Proofs []*types.Proof
	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     didDIDPayload,
		},
		Payload:       base64url.EncodeToString(docBytes),
		CredentialDoc: info,
	}
	proof1 := &did.Proof{
		Type:               "ECDSAsecp256r1",
		VerificationMethod: id1 + "#primary", //"did:elastos:" +
	}
	privateKey1 := base58.Decode(privateKeyStr1)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	proof1.Signature = base64url.EncodeToString(sign)
	//Proofs = append(Proofs, proof1)

	//proof2 := &types.Proof{
	//	Type:               "ECDSAsecp256r1",
	//	VerificationMethod: "did:elastos:" + id2 + "#primary",
	//}
	//privateKey2 := base58.Decode(privateKeyStr2)
	//sign2, _ := crypto.Sign(privateKey2, p.GetData())
	//proof2.Signature = base64url.EncodeToString(sign2)
	//Proofs = append(Proofs, proof2)

	p.Proof = *proof1
	return p
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
	tx1 := getPayloadDIDInfo(id1, "create", docDocBytes, privateKey1Str)

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
	tx2 := getPayloadDIDInfo(id2, "create", issuerDocByts, privateKey2Str)
	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)

	statedb.Prepare(common.HexToHash("0x1234"), common.HexToHash("0x1234"), 1)
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())
	receipt = getCreateDIDReceipt(*tx2)
	rawdb.WriteReceipts(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), common.HexToHash("0x1234"), 0, types.Receipts{receipt})
	statedb.AddDIDLog(id2, did.Create_DID_Operation, buf.Bytes())

	err2 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.HexToHash("0x1234")), 0, 100)
	assert.NoError(t, err2)

	CustomizedDIDTx1 := getCustomizedDIDTx(id1, "create", custIDSingleSignDocBytes1, privateKey1Str)
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
	//this case payload is compact so ignore it
	return
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