package aribiters

import (
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestArbiterManager_RemoveArbiter(t *testing.T) {
	manager := CreateArbiterManager()
	count := 10
	for i := 0; i < count; i++ {
		arbiter := [33]byte{}
		_, err := rand.Read(arbiter[:])
		if err != nil {
			continue
		}
		manager.AddArbiter(arbiter, arbiter[:])
	}
	list := manager.GetArbiterList()

	list1 := manager.GetArbiterList()
	assert.Equal(t, len(list1), count)
	manager.RemoveArbiter(list1[count-1])

	data := manager.FilterArbiters(list)
	assert.Equal(t, len(data), 1)

	for i := 0; i < count; i++ {
		manager.RemoveArbiter(list1[count-i-1])
	}

	list2 := manager.GetArbiterList()
	assert.Equal(t, len(list2), 0)

	data = manager.FilterArbiters(list)
	assert.Equal(t, len(data), count)
}

func TestArbiterManager_FilterSignatures(t *testing.T) {
	manager := CreateArbiterManager()
	count := 3
	signatures := make([]peer.PID, 0)
	for i := 0; i < count; i++ {
		sig := [33]byte{}
		_, err := rand.Read(sig[:])
		if err != nil {
			continue
		}
		manager.AddSignature(sig, sig[:])
		var pid peer.PID
		copy(pid[:], sig[:])
		signatures = append(signatures, pid)
	}
	list1 := manager.GetSignatures()
	assert.Equal(t, len(list1), count)

	list := make([][]byte, 0)
	for _, sig := range list1 {
		list = append(list, sig)
	}

	data := manager.FilterSignatures(list)
	assert.Equal(t, len(data), 0)

	delete(manager.signatures, signatures[0])
	data = manager.FilterSignatures(list)
	assert.Equal(t, len(data), 1)

	delete(manager.signatures, signatures[1])
	data = manager.FilterSignatures(list)
	assert.Equal(t, len(data), 2)

	delete(manager.signatures, signatures[2])
	data = manager.FilterSignatures(list)
	assert.Equal(t, len(data), 3)

}
