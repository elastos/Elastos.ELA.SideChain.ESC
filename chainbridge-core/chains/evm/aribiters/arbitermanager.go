package aribiters

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"

	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

type CollectionInfo struct {
	NextTotalCount    int
	List              [][]byte
	Signatures        map[peer.PID][]byte
	CurrentTotalCount int
}

type ArbiterManager struct {
	nextTotalCount    int
	currentTotalCount int
	arbiters          map[peer.PID][]byte
	signatures        map[peer.PID][]byte

	collectionBox     *CollectionInfo
	consensusArbiters *CollectionInfo
	mtx               sync.RWMutex
}

func CreateArbiterManager() *ArbiterManager {
	manager := &ArbiterManager{
		signatures:        make(map[peer.PID][]byte, 0),
		arbiters:          make(map[peer.PID][]byte, 0),
		collectionBox:     new(CollectionInfo),
		consensusArbiters: new(CollectionInfo),
	}
	manager.consensusArbiters.List = make([][]byte, 0)
	return manager
}

func (a *ArbiterManager) SetTotalCount(nowTotalCount, nextTotalCount int) {
	a.currentTotalCount = nowTotalCount
	a.nextTotalCount = nextTotalCount
}

func (a *ArbiterManager) GetCurrentTotalCount() int {
	return a.currentTotalCount
}

func (a *ArbiterManager) GetNextTotalCount() int {
	return a.nextTotalCount
}

func (a *ArbiterManager) AddArbiter(pid peer.PID, arbiter []byte) error {
	if a.HasArbiterByPID(pid) {
		return errors.New(fmt.Sprintf("AddArbiter failed, has added this arbiter:%s", common.Bytes2Hex(arbiter)))
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.arbiters[pid] = arbiter
	return nil
}

func (a *ArbiterManager) AddCurrentArbiter(arbiter []byte) error {
	if a.HasCurrentArbiter(arbiter) {
		return errors.New(fmt.Sprintf("AddCurrentArbiter failed, has added this current arbiter:%s", common.Bytes2Hex(arbiter)))
	}
	a.mtx.Lock()
	defer a.mtx.Unlock()
	a.consensusArbiters.List = append(a.consensusArbiters.List, arbiter)
	sort.Slice(a.consensusArbiters.List, func(i, j int) bool {
		return bytes.Compare(a.consensusArbiters.List[i][:], a.consensusArbiters.List[j][:]) < 0
	})
	return nil
}

func (a *ArbiterManager) HasCurrentArbiter(signer []byte) bool {
	a.mtx.Lock()
	defer a.mtx.Unlock()
	for _, arbiter := range a.consensusArbiters.List {
		if bytes.Equal(signer, arbiter) {
			return true
		}
	}
	return false
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

func (a *ArbiterManager) RemoveArbiter(arbiter []byte) {
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
	a.consensusArbiters.List = make([][]byte, 0)
}

func (a *ArbiterManager) HashArbiterList(hashSalt *big.Int) (common.Hash, error) {
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
	total := new(big.Int).SetUint64(uint64(a.nextTotalCount))
	totalBytes := common.LeftPadBytes(total.Bytes(), 32)
	data = append(data, totalBytes...)

	saltBytes := common.LeftPadBytes(hashSalt.Bytes(), 32)
	data = append(data, saltBytes...)
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

func (a *ArbiterManager) SaveToCollection() {
	a.mtx.Lock()
	defer a.mtx.Unlock()

	a.collectionBox.List = make([][]byte, 0)
	a.collectionBox.Signatures = make(map[peer.PID][]byte, 0)
	a.collectionBox.NextTotalCount = a.nextTotalCount
	a.collectionBox.CurrentTotalCount = a.currentTotalCount

	for _, item := range a.arbiters {
		a.collectionBox.List = append(a.collectionBox.List, item)
	}
	sort.Slice(a.collectionBox.List, func(i, j int) bool {
		return bytes.Compare(a.collectionBox.List[i][:], a.collectionBox.List[j][:]) < 0
	})

	for key, value := range a.signatures {
		a.collectionBox.Signatures[key] = value
	}
}

func (a *ArbiterManager) GetCollection() CollectionInfo {
	return *a.collectionBox
}

func (a *ArbiterManager) GetConsensusArbiters() CollectionInfo {
	return *a.consensusArbiters
}
