package rawdb

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/elastos/Elastos.ELA/common"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
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

// WritePreimages writes the provided set of preimages to the database.
func WriteDIDImage(db ethdb.Database, didimages map[string][]byte) {
	for id, image := range didimages {
		if err := db.Put([]byte(id), image); err != nil {
			log.Crit("Failed to store trie didImage", "err", err)
		}
	}
}

func PersistRegisterDIDTx(db ethdb.KeyValueStore, logs []*types.Log, blockHeight uint64,
	blockTimeStamp uint64) error {
	var err error
	var buffer *bytes.Reader
	for _, log := range logs {
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
		txHash, err := common.Uint256FromBytes(log.TxHash.Bytes())
		if err != nil {
			return err
		}
		if err := persistRegisterDIDTxHash(db, idKey, *txHash); err != nil {
			return err
		}
		if err := persistRegisterDIDPayload(db, *txHash, operation); err != nil {
			return err
		}
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
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}
		if err := common.WriteUint64(buf, expiresHeight); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current expires height to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
		return err
	}
	if err := common.WriteUint64(buf, expiresHeight); err != nil {
		return err
	}
	if _, err := r.WriteTo(buf); err != nil {
		return err
	}

	return db.Put(key, buf.Bytes())
}

func persistRegisterDIDTxHash(db ethdb.KeyValueStore, idKey []byte, txHash common.Uint256) error {
	key := []byte{byte(IX_DIDTXHash)}
	key = append(key, idKey...)

	data, err := db.Get(key)
	if err != nil {
		// when not exist, only put the current payload hash into db.
		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}

		if err := txHash.Serialize(buf); err != nil {
			return err
		}

		return db.Put(key, buf.Bytes())
	}

	// when exist, should add current payload hash to the end of the list.
	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return err
	}
	count++

	buf := new(bytes.Buffer)

	// write count
	if err := common.WriteVarUint(buf, count); err != nil {
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

func persistRegisterDIDPayload(db ethdb.KeyValueStore, txHash common.Uint256, p *did.Operation) error {
	key := []byte{byte(IX_DIDPayload)}
	key = append(key, txHash.Bytes()...)

	buf := new(bytes.Buffer)
	p.Serialize(buf, did.DIDInfoVersion)
	return db.Put(key, buf.Bytes())
}

func GetDIDFromUri(idURI string) string {
	index := strings.LastIndex(idURI, ":")
	if index == -1 {
		return ""
	}
	return idURI[index+1:]
}

func PersistDeactivateDIDTx(db ethdb.KeyValueStore, logs []string) error {
	for _, id := range logs {
		key := []byte{byte(IX_DIDDeactivate)}
		idKey := []byte(id)
		key = append(key, idKey...)

		buf := new(bytes.Buffer)
		if err := common.WriteVarUint(buf, 1); err != nil {
			return err
		}
		return db.Put(key, buf.Bytes())
	}

	return nil
}