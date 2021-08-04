package msg_pool

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
)

func GenerateProposal(nonce uint64) *voter.Proposal {
	p := &voter.Proposal{
		Source: 1,
		Destination: 2,
		DepositNonce: nonce,
	}
	return p
}

func TestNonceProposal(t *testing.T)  {
	var count = 10
	pool := NewMsgPool()
	for i := 0; i < count; i++ {
		pool.PutProposal(GenerateProposal(uint64(i)))
	}
	list := pool.GetQueueList()
	assert.Equal(t, len(list), count)
	for i := 0; i< count; i++ {
		assert.Equal(t, list[count - i -1].DepositNonce, uint64(i))
		pool.OnProposalExecuted(uint64(i))
	}
	assert.Equal(t, len(pool.queueList), 0)
}
