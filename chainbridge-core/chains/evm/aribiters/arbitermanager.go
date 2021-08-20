package aribiters

import (
	"bytes"
	"errors"
	"sync"
)

type ArbiterManager struct {
	totalCount int
	arbiterList [][]byte
	mtx         sync.RWMutex
}

func CreateArbiterManager() *ArbiterManager {
	manager := &ArbiterManager{
		arbiterList: make([][]byte, 0),
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