package vm

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/state"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did/base64url"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"

	elacom "github.com/elastos/Elastos.ELA/common"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
)
var (
	bankKey, _ = crypto.GenerateKey()
	bankAddr   = crypto.PubkeyToAddress(bankKey.PublicKey)

	userKey1, _ = crypto.GenerateKey()
	userAddr1   = crypto.PubkeyToAddress(userKey1.PublicKey)
)

const (
	PayloadPrivateKey = "a38aa1f5f693a13ef0cf2f1c1c0155cbcdd9386f37b0000739f8cb50af601b7b"
)

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

func Test_checkRegisterDIDTest(t *testing.T)  {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()))
	evm := NewEVM(Context{}, statedb, &params.ChainConfig{}, Config{})

	doc := getPayloadCreateDID()
	err := checkRegisterDID(evm, doc)
	assert.NoError(t, err)

	info := new(did.Operation)
	json.Unmarshal(didPayloadInfoBytes, info)
	payloadBase64, _ := base64url.DecodeString(info.Payload)
	payloadInfo := new(did.DIDPayloadInfo)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.PayloadInfo = payloadInfo

	err = checkRegisterDID(evm, info)
	assert.NoError(t, err)

	info.PayloadInfo.Expires = "Mon Jan _2 15:04:05 2006"
	err = checkRegisterDID(evm, info)
	assert.EqualError(t, err, "invalid Expires")

	info.PayloadInfo.Expires = "2006-01-02T15:04:05Z07:00"
	err = checkRegisterDID(evm, info)
	assert.EqualError(t, err, "invalid Expires")

	info.PayloadInfo.Expires = "2018-06-30T12:00:00Z"
	err = checkRegisterDID(evm, info)
	assert.NoError(t, err)

	info = new(did.Operation)
	json.Unmarshal(errDIDPayloadInfoBytes, info)

	payloadBase64, _ = base64url.DecodeString(info.Payload)
	payloadInfo = new(did.DIDPayloadInfo)
	json.Unmarshal(payloadBase64, payloadInfo)
	info.PayloadInfo = payloadInfo

	err = checkRegisterDID(evm, info)
	assert.EqualError(t, err, "invalid Expires")
}

func getPayloadCreateDID() *did.Operation {
	info := new(did.DIDPayloadInfo)
	json.Unmarshal(didPayloadBytes, info)
	p := &did.Operation{
		Header: did.DIDHeaderInfo{
			Specification: "elastos/did/1.0",
			Operation:     "create",
		},
		Payload: base64url.EncodeToString(didPayloadBytes),
		Proof: did.DIDProofInfo{
			Type:               "ECDSAsecp256r1",
			VerificationMethod: "did:elastos:icJ4z2DULrHEzYSvjKNJpKyhqFDxvYV7pN#default",
		},
		PayloadInfo: info,
	}

	privateKey1, _ := elacom.HexStringToBytes(PayloadPrivateKey)
	sign, _ := elaCrypto.Sign(privateKey1, p.GetData())
	p.Proof.Signature = base64url.EncodeToString(sign)
	return p
}