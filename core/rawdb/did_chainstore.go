package rawdb

import (
	"bytes"
	"errors"
	"strings"
	"time"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"
)

type EntryPrefix byte

const (
	IX_DeactivateCustomizedDID           EntryPrefix = 0x89
	IX_VerifiableCredentialExpiresHeight EntryPrefix = 0x90
	IX_VerifiableCredentialTXHash        EntryPrefix = 0x91
	IX_VerifiableCredentialPayload       EntryPrefix = 0x92
	IX_CUSTOMIZEDDIDPayload              EntryPrefix = 0x93
	IX_CUSTOMIZEDDIDTXHash               EntryPrefix = 0x94
	IX_DIDTXHash                         EntryPrefix = 0x95
	IX_DIDPayload                        EntryPrefix = 0x96
	IX_DIDExpiresHeight                  EntryPrefix = 0x97
	IX_DIDDeactivate                     EntryPrefix = 0x98
	IX_CUSTOMIZEDDIDExpiresHeight        EntryPrefix = 0x99
)

func PersistRegisterDIDTx(db ethdb.KeyValueStore, log *types.DIDLog, blockHeight uint64,
	blockTimeStamp uint64) error {
	var err error
	var buffer *bytes.Reader
	operation := new(did.Operation)
	buffer = bytes.NewReader(log.Data)
	err = operation.Deserialize(buffer, did.DIDInfoVersion)
	if err != nil {
		return err
	}
	id := GetDIDFromUri(operation.PayloadInfo.ID)
	idKey := []byte(id)
	expiresHeight, err := TryGetExpiresHeight(operation.PayloadInfo.Expires, blockHeight, blockTimeStamp)
	if err != nil {
		return err
	}
	if err := persistRegisterDIDExpiresHeight(db, idKey, expiresHeight); err != nil {
		return err
	}
	thash, err := elaCom.Uint256FromBytes(log.TxHash.Bytes())
	if err != nil {
		return err
	}
	if err := persistRegisterDIDTxHash(db, idKey, *thash); err != nil {
		return err
	}
	if err := persistRegisterDIDPayload(db, *thash, operation); err != nil {
		return err
	}
	return nil
}

func TryGetExpiresHeight(Expires string, blockHeight uint64, blockTimeStamp uint64) (uint64, error) {
	expiresTime, err := time.Parse(time.RFC3339, Expires)
	if err != nil {
		return 0, errors.New("invalid Expires")
	}

	var timeSpanSec, expiresSec uint64
	expiresSec = uint64(expiresTime.Unix())
	timeSpanSec = expiresSec - blockTimeStamp

	if expiresSec < blockTimeStamp {
		timeSpanSec = 0
	}
	//needsBlocks := timeSpanSec / (2 * 60)
	needsBlocks := timeSpanSec / 5
	expiresHeight := blockHeight + needsBlocks
	return expiresHeight, nil
}


func persistRegisterDIDExpiresHeight(db ethdb.KeyValueStore, idKey []byte,
	expiresHeight uint64) error {
	key := []byte{byte(IX_DIDExpiresHeight)}
	key = append(key, idKey...)
	data, err := db.Get(key)
	if err != nil {
		// when not exist, only put the current expires height into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func persistRegisterDIDTxHash(db ethdb.KeyValueStore, idKey []byte, txHash elaCom.Uint256) error {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := elaCom.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}
		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := elaCom.WriteVarUint(buf, count); err != nil {
		return err
	}

	// write current payload hash
	if err := txHash.Serialize(buf); err != nil {
		return err
	}

	// write old hashes
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func GetLastDIDTxData(db ethdb.KeyValueStore, idKey []byte) (*did.TranasactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return nil, err
	}

	keyPayload := []byte{byte(IX_DIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := db.Get(keyPayload)
	if err != nil {
		return nil, err
	}

	tempOperation := new(did.Operation)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, did.DIDInfoVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"tempOperation Deserialize failed")
	}
	tempTxData := new(did.TranasactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.PayloadInfo.Expires

	return tempTxData, nil
}

func IsDIDDeactivated(db ethdb.KeyValueStore, did string) bool {
	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey.Bytes()...)

	_, err := db.Get(key)
	if err != nil {
		return false
	}
	return true
}

func GetAllDIDTxTxData(db ethdb.KeyValueStore, idKey []byte) ([]did.TranasactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []did.TranasactionData
	for i := uint64(0); i < count; i++ {
		var txHash elaCom.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		keyPayload := []byte{byte(IX_DIDPayload)}
		keyPayload = append(keyPayload, txHash.Bytes()...)

		payloadData, err := db.Get(keyPayload)
		if err != nil {
			return nil, err
		}
		tempOperation := new(did.Operation)
		r := bytes.NewReader(payloadData)
		err = tempOperation.Deserialize(r, did.DIDInfoVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"payloaddid Deserialize failed")
		}
		tempTxData := new(did.TranasactionData)
		tempTxData.TXID = txHash.String()
		tempTxData.Operation = *tempOperation
		tempTxData.Timestamp = tempOperation.PayloadInfo.Expires
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}

func persistRegisterDIDPayload(db ethdb.KeyValueStore, txHash elaCom.Uint256, p *did.Operation) error {
	key := []byte{byte(IX_DIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, did.DIDInfoVersion)
	return db.Put(key, buf.Bytes())
}

func IsURIHasPrefix(id string) bool {
	return strings.HasPrefix(id, did.DID_ELASTOS_PREFIX)
}

func GetDIDFromUri(idURI string) string {
	index := strings.LastIndex(idURI, ":")
	if index == -1 {
		return ""
	}
	return idURI[index+1:]
}

func PersistDeactivateDIDTx(db ethdb.KeyValueStore, log *types.DIDLog) error {
	key := []byte{byte(IX_DIDDeactivate)}
	idKey := []byte(log.DID)
	key = append(key, idKey...)

	buf := new(bytes.Buffer)
	if err := elaCom.WriteVarUint(buf, 1); err != nil {
		return err
	}
	return db.Put(key, buf.Bytes())
}

func GetAllVerifiableCredentialTxData(db ethdb.KeyValueStore, idKey []byte) ([]did.VerifiableCredentialTxData, error) {
	key := []byte{byte(IX_VerifiableCredentialTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	var transactionsData []did.VerifiableCredentialTxData
	for i := uint64(0); i < count; i++ {
		var txHash elaCom.Uint256
		if err := txHash.Deserialize(r); err != nil {
			return nil, err
		}
		keyPayload := []byte{byte(IX_VerifiableCredentialPayload)}
		keyPayload = append(keyPayload, txHash.Bytes()...)

		payloadData, err := db.Get(keyPayload)
		if err != nil {
			return nil, err
		}
		vcPayload := new(did.VerifiableCredentialPayload)
		r := bytes.NewReader(payloadData)
		err = vcPayload.Deserialize(r, did.VerifiableCredentialVersion)
		if err != nil {
			return nil, http.NewError(int(service.InvalidTransaction),
				"verifiable credential payload Deserialize failed")
		}
		tempTxData := new(did.VerifiableCredentialTxData)
		tempTxData.TXID = txHash.String()
		tempTxData.Timestamp = vcPayload.Doc.ExpirationDate
		tempTxData.Operation = *vcPayload
		transactionsData = append(transactionsData, *tempTxData)
	}

	return transactionsData, nil
}
