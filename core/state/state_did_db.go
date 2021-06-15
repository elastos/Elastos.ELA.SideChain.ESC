package state

import (
	"bytes"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
)

type EntryPrefix byte

func (self *StateDB) AddDIDLog(did string, operation string, doc []byte) {
	self.journal.append(didLogChange{txhash: self.thash})
	pi := make([]byte, len(doc))
	copy(pi, doc)
	log := &types.DIDLog{
		DID: did,
		Operation: operation,
		Data: pi,
		TxHash: self.thash,
	}
	self.didLogs[self.thash] = log
}

func (self *StateDB) GetDIDLog(txHash common.Hash) *types.DIDLog {
	if self.didLogs[txHash] == nil {
		return &types.DIDLog{}
	}
	return self.didLogs[txHash]
}

func (self *StateDB) DIDLogs() []*types.DIDLog {
	var logs []*types.DIDLog
	for _, lgs := range self.didLogs {
		logs = append(logs, lgs)
	}
	return logs
}

func (self *StateDB) RemoveDIDLog(txHash common.Hash) {
	if self.didLogs[txHash] != nil {
		delete(self.didLogs, txHash)
	}
}

func (self *StateDB) IsDIDDeactivated(did string) bool {
	return rawdb.IsDIDDeactivated(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), did)
}

func (self *StateDB) GetLastDIDTxData(idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error) {
	logs := self.DIDLogs()
	did := string(idKey)
	for _, log := range logs {
		if log.DID == did {
		   return nil, errors.New("allready create did: " + did)
		}
	}
	return rawdb.GetLastDIDTxData(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), idKey, config)
}

func (self *StateDB) GetAllDIDTxData(idKey []byte, config *params.ChainConfig) ([]did.DIDTransactionData, error) {
	logs := self.DIDLogs()
	id := string(idKey)
	for _, log := range logs {
		if log.DID == id {
			return nil, errors.New("allready create did: " + id)
		}
	}
	return rawdb.GetAllDIDTxTxData(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), idKey, config)
}

func (self *StateDB) GetLastCustomizedDIDTxData(idKey []byte) (*did.DIDTransactionData, error) {
	key := []byte{byte(rawdb.IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := self.db.TrieDB().DiskDB().Get(key)
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

	keyPayload := []byte{byte(rawdb.IX_CUSTOMIZEDDIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := self.db.TrieDB().DiskDB().Get(keyPayload)
	if err != nil {
		return nil, err
	}

	tempOperation := new(did.DIDPayload)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, did.DIDVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"CustomizedDIDOperation Deserialize failed")
	}
	tempTxData := new(did.DIDTransactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.GetDIDDoc().Expires

	return tempTxData, nil
}

func (self *StateDB) GetLastCustomizedDIDTxHash(idKey []byte) (elaCom.Uint256, error) {
	key := []byte{byte(rawdb.IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := self.db.TrieDB().DiskDB().Get(key)
	if err != nil {
		return elaCom.Uint256{}, err
	}

	r := bytes.NewReader(data)
	count, err := elaCom.ReadVarUint(r, 0)
	if err != nil {
		return elaCom.Uint256{}, err
	}
	if count == 0 {
		return elaCom.Uint256{}, errors.New("not exist")
	}
	var txHash elaCom.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return elaCom.Uint256{}, err
	}

	return txHash, nil
}


func (self *StateDB) GetLastVerifiableCredentialTxData(idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error) {
	return rawdb.GetLastVerifiableCredentialTxData(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), idKey, config)
}

func (self *StateDB) IsDID(did string)  (bool, error) {
	return rawdb.IsDID(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), did)
}

func (self *StateDB) ReadTransaction(txID common.Hash) (*types.Transaction, common.Hash, uint64, uint64) {
	return rawdb.ReadTransaction(self.db.TrieDB().DiskDB().(ethdb.Database), txID)
}

func (self *StateDB) ReadBlock(hash common.Hash, number uint64) *types.Block {
	return rawdb.ReadBlock(self.db.TrieDB().DiskDB().(ethdb.Database), hash, number)
}

func (self *StateDB) GetDeactivatedTxData(idKey []byte, config *params.ChainConfig) (*did.DIDTransactionData, error)  {
	return rawdb.GetDeactivatedTxData(self.db.TrieDB().DiskDB().(ethdb.Database), idKey, config)
}