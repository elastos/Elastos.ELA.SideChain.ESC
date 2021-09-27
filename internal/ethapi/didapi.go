package ethapi

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/internal/didapi"
)

// payload of DID transaction
type RpcCredentialPayloadDIDInfo struct {
	ID         string                         `json:"id"`
	Status     int                            `json:"status"`
	RpcTXDatas []RpcCredentialTransactionData `json:"transaction,omitempty"`
}

type RpcCredentialTransactionData struct {
	TXID      string              `json:"txid"`
	Timestamp string              `json:"timestamp"`
	Operation CredentialOperation `json:"operation"`
}

type CredentialOperation struct {
	Header  did.Header  `json:"header"`
	Payload string      `json:"payload"`
	Proof   interface{} `json:"proof"`
}

//xxl add new register API
// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the Ethereum service.
func NewPublicDIDAPI(b Backend, nonceLock *AddrLocker) *PublicTransactionPoolAPI {
	return &PublicTransactionPoolAPI{b, nonceLock}
}

func (rpcTxData *RpcCredentialTransactionData) FromCredentialTranasactionData(txData did.
	VerifiableCredentialTxData) bool {
	hash, err := elacom.Uint256FromHexString(txData.TXID)
	if err != nil {
		return false
	}

	rpcTxData.TXID = service.ToReversedString(*hash)
	rpcTxData.Timestamp = txData.Timestamp
	rpcTxData.Operation.Header = txData.Operation.Header
	rpcTxData.Operation.Payload = txData.Operation.Payload
	rpcTxData.Operation.Proof = txData.Operation.Proof
	return true
}

func (s *PublicTransactionPoolAPI) ResolveCredential(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	idParam, ok := param["id"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "id is null")
	}
	credentialID := idParam
	buf := new(bytes.Buffer)
	buf.WriteString(credentialID)
	txsData, _ := rawdb.GetAllVerifiableCredentialTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())

	issuer, ok := param["issuer"].(string)
	var issuerID string
	if issuer != "" {
		issuerID = issuer
	}

	var rpcPayloadDid RpcCredentialPayloadDIDInfo
	for index, txData := range txsData {
		rpcPayloadDid.ID = txData.Operation.CredentialDoc.ID
		err, timestamp := s.getTxTime(ctx, txData.TXID)
		if err != nil {
			continue
		}
		tempTXData := new(RpcCredentialTransactionData)
		ok := tempTXData.FromCredentialTranasactionData(txData)
		if !ok {
			continue
		}

		var isRevokeTransaction bool
		if len(txsData) == 2 && index == 0 {
			isRevokeTransaction = true
		}

		signer := txData.Operation.Proof.VerificationMethod
		if isRevokeTransaction && issuerID == "" && signer == txData.Operation.CredentialDoc.Issuer {
			continue
		}

		if isRevokeTransaction && issuerID != "" && signer != issuerID {
			continue
		}

		tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
	}

	if len(txsData) == 0 {
		rpcPayloadDid.Status = didapi.CredentialNonExist
	} else if len(txsData) == 1 {
		rpcPayloadDid.Status = didapi.CredentialValid
	} else if len(txsData) == 2 {
		rpcPayloadDid.Status = didapi.CredentialRevoked
	}

	return rpcPayloadDid, nil
}

func (s *PublicTransactionPoolAPI) getDeactiveTx(ctx context.Context, idKey []byte) (*didapi.RpcTranasactionData, error) {
	//get deactive tx date
	deactiveTxData, err := rawdb.GetDeactivatedTxData(s.b.ChainDb().(ethdb.KeyValueStore), idKey,
		s.b.ChainConfig())
	if err != nil {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	//change from DIDTransactionData to RpcTranasactionData
	rpcTXData := new(didapi.RpcTranasactionData)
	succe := rpcTXData.FromTranasactionData(*deactiveTxData)
	if succe == false {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	//fill tx Timestamp
	err, timestamp := s.getTxTime(ctx, rpcTXData.TXID)
	if err != nil {
		return nil, http.NewError(int(service.InternalError),
			"get did deactivate transaction failed")
	}
	rpcTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
	return rpcTXData, nil
}

//xxl modify to PublicTransactionPoolAPI
func (s *PublicTransactionPoolAPI) ResolveDID(ctx context.Context, param map[string]interface{}) (interface{}, error) {
	var didDocState didapi.DidDocState = didapi.NonExist

	idParam, ok := param["did"].(string)
	if !ok {
		return nil, http.NewError(int(service.InvalidParams), "did is null")
	}
	//remove DID_ELASTOS_PREFIX
	id := idParam
	if rawdb.IsURIHasPrefix(idParam) {
		id = did.GetDIDFromUri(id)
	}else{
		//add prefix
		idParam = did.DID_ELASTOS_PREFIX+ idParam
	}

	//check is valid address
	_, err := elacom.Uint168FromAddress(id)
	if err != nil {
		return nil, http.NewError(int(service.InvalidParams), "invalid did")
	}

	isGetAll, ok := param["all"].(bool)
	if !ok {
		isGetAll = false
	}

	var rpcPayloadDid didapi.RpcPayloadDIDInfo

	buf := new(bytes.Buffer)
	buf.WriteString(idParam)
	txData, err := rawdb.GetLastDIDTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
	if err != nil {
		rpcPayloadDid.DID = idParam
		rpcPayloadDid.Status = didapi.NonExist
		return rpcPayloadDid, nil
	}

	var txsData []did.DIDTransactionData
	if isGetAll {
		txsData, err = rawdb.GetAllDIDTxTxData(s.b.ChainDb().(ethdb.KeyValueStore), buf.Bytes(), s.b.ChainConfig())
		if err != nil {
			return nil, http.NewError(int(service.InternalError),
				"get did transaction failed")
		}

	} else {
		if txData != nil {
			txsData = append(txsData, *txData)
		}
	}

	for index, txData := range txsData {
		rpcPayloadDid.DID = txData.Operation.DIDDoc.ID
		err, timestamp := s.getTxTime(ctx, txData.TXID)
		if err != nil {
			continue
		}
		tempTXData := new(didapi.RpcTranasactionData)
		succe := tempTXData.FromTranasactionData(txData)
		if succe == false {
			continue
		}

		tempTXData.Timestamp = time.Unix(int64(timestamp), 0).UTC().Format(time.RFC3339)
		if index == 0 {
			if rawdb.IsDIDDeactivated(s.b.ChainDb().(ethdb.KeyValueStore), idParam) {
				didDocState = didapi.Deactivated
				//fill in
				deactiveTXData, err := s.getDeactiveTx(ctx, buf.Bytes())
				if err != nil {
					return nil, err
				}
				rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *deactiveTXData)
			} else {
				didDocState = didapi.Valid
			}
			rpcPayloadDid.Status = int(didDocState)
		}
		rpcPayloadDid.RpcTXDatas = append(rpcPayloadDid.RpcTXDatas, *tempTXData)
	}
	return rpcPayloadDid, nil
}

func (s *PublicTransactionPoolAPI) getTxTime(ctx context.Context, txid string) (error, uint64) {
	hash := common.HexToHash(txid)

	tx, err := s.GetTransactionByHash(ctx, hash)
	if err != nil || tx == nil {
		return errors.New("unkown tx"), 0
	}
	block, err := s.b.BlockByHash(ctx, *tx.BlockHash)
	if err != nil {
		return errors.New("unkown block header"), 0

	}
	return nil, block.Time()
}
