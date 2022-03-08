package msg_pool

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/voter"
)

func GenerateProposal(nonce uint64) *voter.Proposal {
	data := common.LeftPadBytes(big.NewInt(int64(nonce)).Bytes(), 32)
	data2 := common.LeftPadBytes(big.NewInt(int64(nonce)).Bytes(), 32)
	data = append(data, data2...)
	p := &voter.Proposal{
		Source:       1,
		Destination:  2,
		DepositNonce: nonce,
		Data:         data,
	}
	return p
}

func TestNonceProposal(t *testing.T) {
	var count = 10
	pool := NewMsgPool([]byte{})
	for i := 0; i < count; i++ {
		pool.PutProposal(GenerateProposal(uint64(count - i - 1)))
	}

	list := pool.GetQueueList()
	assert.Equal(t, len(list), count)
	for i := 0; i < count; i++ {
		assert.Equal(t, list[i].DepositNonce, uint64(i))
		pool.OnProposalExecuted(uint64(i))
	}
	assert.Equal(t, len(pool.queueList), 0)
}
