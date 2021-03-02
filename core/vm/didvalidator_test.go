package vm

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
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

	id1DocByts     []byte
	id2DocByts     []byte
	id11DocByts    []byte
	idUser1DocByts []byte
	idUser2DocByts []byte
	customizedDIDDocSingleContrller []byte
	customizedDIDDocBytes2          []byte

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
	customizedDIDDocBytes2, _ = LoadJsonData("./testdata/foo.id.json")//
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

func Test_checkRegisterDIDTest(t *testing.T)  {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	var gas uint64 = 20000
	doc := getPayloadCreateDID()
	err := checkRegisterDID(evm, doc, gas)
	assert.NoError(t, err)

	info := new(did.DIDPayload)
	json.Unmarshal(didPayloadInfoBytes, info)
	payloadBase64, _ := base64url.DecodeString(info.Payload)
	payloadInfo := new(did.DIDDoc)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.DIDDoc = payloadInfo

	err = checkRegisterDID(evm, info, gas)
	assert.NoError(t, err)

	info.DIDDoc.Expires = "Mon Jan _2 15:04:05 2006"
	err = checkRegisterDID(evm, info,  gas)
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
	id1 := "did:elastos:iWFAUYhTa35c1fPe3iCJvihZHx6quumnym"
	privateKey1Str := "41Wji2Bo39wLB6AoUP77ADANaPeDBQLXycp8rzTcgLNW"

	id2 := "did:elastos:ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	privateKey2Str := "9sYYMSsS2xDbGvSRhNSnMsTbCbF2LPwLovRH93drSetM"

	tx2 := getPayloadDIDInfo(id2, "create", id2DocByts, privateKey2Str)
	tx1 := getPayloadDIDInfo(id1, "create", id1DocByts, privateKey1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})
	id := "ir31cZZbBQUFbp4pNpMQApkAyJ9dno3frB"
	buf := new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id, did.Create_DID_Operation, buf.Bytes())
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 100, 123456)
	assert.NoError(t, err1)
	err2 := checkRegisterDID(evm, tx1, 2000)
	assert.NoError(t, err2)
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

func Test_checkDeactivateDIDTest(t *testing.T) {
	didWithPrefix := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j"
	verifDid := "did:elastos:iTWqanUovh3zHfnExGaan4SJAXG3DCZC6j#default"
	id := rawdb.GetDIDFromUri(didWithPrefix)

	txCreateDID := getPayloadCreateDID()
	payload := getPayloadDeactivateDID(didWithPrefix, verifDid)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	//Deactive did  have no
	err := checkDeactivateDID(evm, payload)
	assert.EqualError(t, err, ErrNotFound.Error())

	buf := new(bytes.Buffer)
	txCreateDID.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id, did.Create_DID_Operation, buf.Bytes())
	err = rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 0)
	assert.NoError(t, err)

	err = checkDeactivateDID(evm, payload)
	assert.NoError(t, err)

	//wrong public key to verify sign
	verifDid = "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#master"
	payload = getPayloadDeactivateDID(didWithPrefix, verifDid)
	err = checkDeactivateDID(evm, payload)
	assert.EqualError(t, err, "[VM] Check Sig FALSE")

	//deactive one deactivated did
	statedb.AddDIDLog(id, did.Deactivate_DID_Operation, buf.Bytes())
	rawdb.PersistDeactivateDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}))
	txDeactivateWrong := getPayloadDeactivateDID(didWithPrefix, verifDid)
	err = checkDeactivateDID(evm, txDeactivateWrong)
	assert.EqualError(t, err, "DID WAS AREADY DEACTIVE")
}


func getPayloadDeactivateDID(id, verifDid string) *did.DIDPayload {
	info := new(did.DIDDoc)
	json.Unmarshal(didPayloadBytes, info)

	p := &did.DIDPayload{
		Header: did.Header{
			Specification: "elastos/did/1.0",
			Operation:     "create",
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
	id1 := "imUUPBfrZ1yZx6nWXe6LNN59VeX2E6PPKj"
	privateKey1Str := "413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ" //413uivqLEMjPd8bo42K9ic6VXpgYcJLEwB3vefxJDhXJ
	tx1 := getPayloadDIDInfo(id1, "create", id11DocByts, privateKey1Str)


	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(id1, did.Create_DID_Operation, buf.Bytes())
	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 0, 100)
	assert.NoError(t, err1)

	//examplercorp.id.json
	didParam.IsTest = true
	tx3 := getCustomizedDIDDoc(id1, "create", customizedDIDDocSingleContrller, privateKey1Str)
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
	idUser1 := "iXcRhYB38gMt1phi5JXJMjeXL2TL8cg58y"
	privateKeyUser1Str := "3z2QFDJE7woSUzL6az9sCB1jkZtzfvEZQtUnYVgQEebS"
	tx1 := getPayloadDIDInfo(idUser1, "create", idUser1DocByts, privateKeyUser1Str)

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	buf := new(bytes.Buffer)
	tx1.Serialize(buf, did.DIDVersion)
	statedb.AddDIDLog(idUser1, did.Create_DID_Operation, buf.Bytes())

	err1 := rawdb.PersistRegisterDIDTx(statedb.Database().TrieDB().DiskDB().(ethdb.KeyValueStore), statedb.GetDIDLog(common.Hash{}), 100, 123456)
	assert.NoError(t, err1)

	privateKeyUser2Str := "AqBB8Uur4QwwBtFPeA2Yd5yF2Ni45gyz2osfFcMcuP7J"
	idUser2 := "idwuEMccSpsTH4ZqrhuHqg6y8XMVQAsY5g"
	tx2 := getPayloadDIDInfo(idUser2, "create", idUser2DocByts, privateKeyUser2Str)

	buf = new(bytes.Buffer)
	tx2.Serialize(buf, did.DIDVersion)
	statedb.Prepare(common.HexToHash("0x1234"), common.HexToHash("0x1234"), 1)
	statedb.AddDIDLog(idUser2, did.Create_DID_Operation, buf.Bytes())
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
		VerificationMethod: "did:elastos:" + id1 + "#primary",
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
			VerificationMethod: "did:elastos:" + id + "#primary",
		},
		DIDDoc: info,
	}
	privateKey1 := base58.Decode(privateKeyStr)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}
