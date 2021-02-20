package state

import (
	"bytes"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm/did"
	"github.com/elastos/Elastos.ELA.SideChain/service"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/utils/http"
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

func (self *StateDB) DIDChange() map[string][]byte {
	return self.didimages
}

func (self *StateDB) CreateDID(did string, doc []byte) {
	self.journal.append(createDIDChange{did:did})
	pi := make([]byte, len(doc))
	copy(pi, doc)
	self.didimages[did] = pi
}

func (self *StateDB) GetDID(did string) ([]byte, error) {
	if data := self.didimages[did]; data != nil {
		return data, nil
	}
	if data, err := self.db.TrieDB().DiskDB().Get([]byte(did)); err == nil {
		return data, nil
	}
	return nil, errors.New("not create did")
}

func (self *StateDB) IsDIDDeactivated(did string) bool {
	if data := self.deactivateimages[did]; data != false {
		return true
	}

	idKey := new(bytes.Buffer)
	idKey.WriteString(did)

	key := []byte{byte(IX_DIDDeactivate)}
	key = append(key, idKey.Bytes()...)

	if _, err := self.db.TrieDB().DiskDB().Get(key); err != nil {
		return false
	}
	return true
}

func (self *StateDB) GetLastDIDTxData(idKey []byte) (*did.TranasactionData, error) {
	key := []byte{byte(IX_DIDTXHash)}
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

	keyPayload := []byte{byte(IX_DIDPayload)}
	keyPayload = append(keyPayload, txHash.Bytes()...)

	dataPayload, err := self.db.TrieDB().DiskDB().Get(keyPayload)
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