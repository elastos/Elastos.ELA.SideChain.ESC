package aribiters

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"

	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

type ArbiterManager struct {
	totalCount int
	arbiters map[peer.PID][]byte
	signatures  map[peer.PID][]byte
	mtx         sync.RWMutex
}

func CreateArbiterManager() *ArbiterManager {
	manager := &ArbiterManager{
		signatures:  make(map[peer.PID][]byte, 0),
		arbiters: make(map[peer.PID][]byte, 0),
	}
	return manager
}

func (a *ArbiterManager) SetTotalCount(count int) {
	a.totalCount = count
}

func (a *ArbiterManager) GetTotalCount() int {
	return a.totalCount
}

func (a *ArbiterManager) AddArbiter(pid peer.PID, arbiter []byte) error {
	if a.HasArbiterByPID(pid) {
		return errors.New("has added this arbiter")
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiters[pid] = arbiter
	return nil
}

func (a *ArbiterManager) HasArbiterByPID(pid peer.PID) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return len(a.arbiters[pid]) > 0
}

func (a *ArbiterManager) HasArbiter(arbiter []byte) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	for _, arb := range a.arbiters {
		if bytes.Equal(arb, arbiter) {
			return true
		}
	}
	return false
}

func (a *ArbiterManager) RemoveArbiter(arbiter []byte)  {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for index, item := range a.arbiters {
		if bytes.Equal(item, arbiter) {
			delete(a.arbiters, index)
			break
		}
	}
}

func (a *ArbiterManager) GetArbiterList() [][]byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	list := make([][]byte, 0)
	for _, item := range a.arbiters {
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
	a.arbiters = make(map[peer.PID][]byte, 0)
	a.signatures = make(map[peer.PID][]byte, 0)
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

func (a *ArbiterManager) AddSignature(pid peer.PID, signature []byte) error {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	if len(a.signatures[pid]) > 0 {
		return errors.New(fmt.Sprintf("all ready add this signature:%s", pid.String()))
	}
	a.signatures[pid] = signature
	return nil
}

func (a *ArbiterManager) GetSignatures() map[peer.PID][]byte {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	return a.signatures
}

func (a *ArbiterManager) HasSignature(pid []byte) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	var peer peer.PID
	copy(peer[:], pid)
	return len(a.signatures[peer]) > 0
}

func (a *ArbiterManager) FilterArbiters(peers [][]byte) [][]byte {
	list := make([][]byte, 0)
	for _, p := range peers {
		list = append(list, p)
	}
	if len(a.arbiters) <= 0 {
		return list
	}
	for i := 0; i < len(list); {
		for peer, _ := range a.arbiters {
			if bytes.Equal(list[i], peer[:]) {
				list = append(list[:i], list[i+1:]...)
				i--
				break
			}
		}
		i++
	}
	return list
}

func (a *ArbiterManager) FilterSignatures(peers [][]byte) [][]byte {
	list := make([][]byte, 0)
	for _, p := range peers {
		list = append(list, p)
	}
	if len(a.signatures) <= 0 {
		return list
	}
	for i := 0; i < len(list); {
		for peer, _ := range a.signatures {
			if bytes.Equal(list[i], peer[:]) {
				list = append(list[:i], list[i+1:]...)
				i--
				break
			}
		}
		i++
	}
	return list
}