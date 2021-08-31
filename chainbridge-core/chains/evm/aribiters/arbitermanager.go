package aribiters

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"

)

type ArbiterManager struct {
	totalCount int
	arbiterList [][]byte
	signatures  map[string][]byte
	mtx         sync.RWMutex
}
// make(map[[2]enode.ID]struct{}, total)
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
	if a.HashArbiter(arbiter) {
		return errors.New("has added this arbiter")
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiterList = append(a.arbiterList, arbiter)
	return nil
}

func (a *ArbiterManager) HashArbiter(arbiter []byte) bool {
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
	return list
}

func (a *ArbiterManager) Clear() {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiterList = make([][]byte, 0)
	a.signatures = make(map[string][]byte, 0)
}

func (a *ArbiterManager) HashArbiterList() common.Hash {
	list := a.GetArbiterList()
	sort.Slice(list, func(i, j int) bool {
		return bytes.Compare(list[i][:], list[j][:]) < 0
	})
	data := make([]byte, 0)
	for _, ar := range list {
		data = append(data, ar...)
	}
	return crypto.Keccak256Hash(data)
}

func (a *ArbiterManager) AddSignature(arbiter, signature []byte) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	arb := common.Bytes2Hex(arbiter)
	fmt.Println("[AddSignature]", "a.signatures[arb]", common.Bytes2Hex(a.signatures[arb]))
	if a.signatures[arb] != nil || len(a.signatures[arb]) > 0 {
		return errors.New("all ready add this signature")
	}
	a.signatures[arb] = signature
	return nil
}

func (a *ArbiterManager) GetSignatures() map[string][]byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.signatures
}