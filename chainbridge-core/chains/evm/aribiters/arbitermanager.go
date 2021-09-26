package aribiters

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
)

type ArbiterManager struct {
	totalCount int
	arbiterList [][]byte
	signatures  map[string][]byte
	mtx         sync.RWMutex
}

func CreateArbiterManager() *ArbiterManager {
	manager := &ArbiterManager{
		arbiterList: make([][]byte, 0),
		signatures:  make(map[string][]byte, 0),
	}
	return manager
}

func (a *ArbiterManager) SetTotalCount(count int) {
	a.totalCount = count
}

func (a *ArbiterManager) GetTotalCount() int {
	return a.totalCount
}

func (a *ArbiterManager) AddArbiter(arbiter []byte) error {
	if a.HasArbiter(arbiter) {
		return errors.New("has added this arbiter")
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiterList = append(a.arbiterList, arbiter)
	return nil
}

func (a *ArbiterManager) HasArbiter(arbiter []byte) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for _, item := range a.arbiterList {
		if bytes.Equal(item, arbiter) {
			return true
		}
	}
	return false
}

func (a *ArbiterManager) RemoveArbiter(arbiter []byte)  {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for index, item := range a.arbiterList {
		if bytes.Equal(item, arbiter) {
			a.arbiterList = append(a.arbiterList[:index], a.arbiterList[index+1:]...)
			break
		}
	}
}

func (a *ArbiterManager) GetArbiterList() [][]byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	list := make([][]byte, 0)
	for _, item := range a.arbiterList {
		list = append(list, item)
	}
	sort.Slice(list, func(i, j int) bool {
		return bytes.Compare(list[i][:], list[j][:]) < 0
	})
	return list
}

func (a *ArbiterManager) Clear() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiterList = make([][]byte, 0)
	a.signatures = make(map[string][]byte, 0)
}

func (a *ArbiterManager) HashArbiterList() (common.Hash, error) {
	arbiters := a.GetArbiterList()
	data := make([]byte, 0)
	for _, arbiter := range arbiters {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			return common.Hash{}, err
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		data = append(data, addr.Bytes()...)
	}
	return crypto.Keccak256Hash(data), nil
}

func (a *ArbiterManager) AddSignature(arbiter common.Address, signature []byte) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	var addr common.Address
	if arbiter == addr {
		return errors.New("is black hole address")
	}

	arb := arbiter.String()
	if len(a.signatures[arb]) > 0 {
		return errors.New(fmt.Sprintf("all ready add this signature:%s", arb))
	}
	a.signatures[arb] = signature
	return nil
}

func (a *ArbiterManager) GetSignatures() map[string][]byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.signatures
}