package state

import (
	"bytes"
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
)

type EntryPrefix byte

func (self *StateDB) AddDIDLog(did string, operation byte, doc []byte) {
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

func (self *StateDB) IsDIDDeactivated(did string) bool {
	return rawdb.IsDIDDeactivated(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), did)
}

func (self *StateDB) GetLastDIDTxData(idKey []byte) (*did.TranasactionData, error) {
	return rawdb.GetLastDIDTxData(self.db.TrieDB().DiskDB().(ethdb.KeyValueStore), idKey)
}

func (self *StateDB) GetLastCustomizedDIDTxData(idKey []byte) (*did.CustomizedDIDTranasactionData, error) {
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

	tempOperation := new(did.CustomizedDIDOperation)
	r = bytes.NewReader(dataPayload)
	err = tempOperation.Deserialize(r, did.CustomizedDIDVersion)
	if err != nil {
		return nil, http.NewError(int(service.ResolverInternalError),
			"CustomizedDIDOperation Deserialize failed")
	}
	tempTxData := new(did.CustomizedDIDTranasactionData)
	tempTxData.TXID = txHash.String()
	tempTxData.Operation = *tempOperation
	tempTxData.Timestamp = tempOperation.GetPayloadInfo().Expires

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