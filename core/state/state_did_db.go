package state

import (
	"bytes"
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"

	"github.com/elastos/Elastos.ELA.SideChain/service"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
)

type EntryPrefix byte

func (self *StateDB) AddDIDLog(did string, doc []byte) {
	self.journal.append(didLogChange{did: did})
	pi := make([]byte, len(doc))
	copy(pi, doc)
	log := &types.Log{
		Data: pi,
		TxHash: self.thash,
		BlockHash: self.bhash,
	}
	self.didLogs[did] = log
}

func (self *StateDB) GetDID(did string) *types.Log {
	return self.didLogs[did]
}

func (self *StateDB) DIDLogs() []*types.Log {
	var logs []*types.Log
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
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("not exist")
	}
	var txHash common.Uint256
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

func (self *StateDB) GetLastCustomizedDIDTxHash(idKey []byte) (common.Uint256, error) {
	key := []byte{byte(rawdb.IX_CUSTOMIZEDDIDTXHash)}
	key = append(key, idKey...)

	data, err := self.db.TrieDB().DiskDB().Get(key)
	if err != nil {
		return common.Uint256{}, err
	}

	r := bytes.NewReader(data)
	count, err := common.ReadVarUint(r, 0)
	if err != nil {
		return common.Uint256{}, err
	}
	if count == 0 {
		return common.Uint256{}, errors.New("not exist")
	}
	var txHash common.Uint256
	if err := txHash.Deserialize(r); err != nil {
		return common.Uint256{}, err
	}

	return txHash, nil
}

func (self *StateDB) ADDDeactiveDIDLog(did string) {
	self.journal.append(didLogChange{did: did})
	self.deactiveDID[did] = true
}

func (self *StateDB) DeactiveDIDLog() []string {
	var logs []string
	for id, lgs := range self.deactiveDID {
		if lgs == true {
			logs = append(logs, id)
		}
	}
	return logs
}