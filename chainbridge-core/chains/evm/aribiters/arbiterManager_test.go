package aribiters

import (
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
		manager.AddArbiter(arbiter[:])
	}

	list1 := manager.GetArbiterList()
	assert.Equal(t, len(list1), count)
	manager.RemoveArbiter(list1[count-1])

	for i := 0; i < count; i ++ {
		manager.RemoveArbiter(list1[count- i - 1])
	}

	list2 := manager.GetArbiterList()
	assert.Equal(t, len(list2), 0)
}
