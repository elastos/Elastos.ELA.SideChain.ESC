package didapi

import (
	"encoding/json"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm/did/base64url"

	elacom "github.com/elastos/Elastos.ELA/common"
)

type DidDocState uint8

const (
	Valid = iota
	Expired
	Deactivated
	NonExist
)

func (c DidDocState) String() string {
	switch c {
	case Valid:
		return "Valid"
	case Expired:
		return "Expired"
	case Deactivated:
		return "Deactivated"
	case NonExist:
		return "NonExist"
	default:
		return "Unknown"
	}
}

const (
	CredentialValid = iota
	CredentialReserve
	CredentialRevoked
	CredentialNonExist
)

// payload of DID transaction
type RpcPayloadDIDInfo struct {
	DID        string                `json:"did"`
	Status     int                   `json:"status"`
	RpcTXDatas []RpcTranasactionData `json:"transaction,omitempty"`
}

type RpcOperation struct {
	Header  did.Header `json:"header"`
	Payload string     `json:"payload"`
	Proof   did.Proof  `json:"proof"`
}

type RpcTranasactionData struct {
	TXID      string       `json:"txid"`
	Timestamp string       `json:"timestamp"`
	Operation RpcOperation `json:"operation"`
}

func (rpcTxData *RpcTranasactionData) FromTranasactionData(txData did.DIDTransactionData) bool {
	hash, err := elacom.Uint256FromHexString(txData.TXID)
	if err != nil {
		return false
	}

	rpcTxData.TXID = hash.String() //service.ToReversedString(*hash)
	rpcTxData.Timestamp = txData.Timestamp
	rpcTxData.Operation.Header = txData.Operation.Header
	rpcTxData.Operation.Payload = txData.Operation.Payload
	rpcTxData.Operation.Proof = txData.Operation.Proof
	return true
}

func (rpcTxData *RpcTranasactionData) ToResolveTxData() ResolveTranasactionData {
	var data ResolveTranasactionData
	data.Timestamp = rpcTxData.Timestamp
	data.TXID = rpcTxData.TXID

	data.Operation.Header = rpcTxData.Operation.Header
	data.Operation.Proof = rpcTxData.Operation.Proof

	payloadBase64, _ := base64url.DecodeString(rpcTxData.Operation.Payload)
	payloadInfo := new(did.DIDDoc)
	if err := json.Unmarshal(payloadBase64, payloadInfo); err == nil {
		data.Operation.Payload = *payloadInfo
	}
	return data
}

// resolve payload of DID transaction
type ResolvePayloadDIDInfo struct {
	DID        string                	 `json:"did"`
	Status     int                   	 `json:"status"`
	RpcTXDatas []ResolveTranasactionData `json:"transaction,omitempty"`
}

type ResolveTranasactionData struct {
	TXID      string       	   `json:"txid"`
	Timestamp string       	   `json:"timestamp"`
	Operation ResolveOperation `json:"operation"`
}

type ResolveOperation struct {
	Header  did.Header `json:"header"`
	Payload did.DIDDoc `json:"payload"`
	Proof   did.Proof  `json:"proof"`
}