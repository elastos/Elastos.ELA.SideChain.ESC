package voter

import (
	"bytes"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

func TestProposal_Serialize(t *testing.T) {
	p := Proposal{
		Source: 1,
		DepositNonce: rand.Uint64(),
		ResourceId: common.Hash([]byte{1,2,3}),
		Data: []byte{1,2,3,4,5},
	}

	w := bytes.NewBuffer([]byte{})
	err := p.Serialize(w)
	assert.NoError(t, err)

	proposal := &Proposal{}
	proposal.Deserialize(w)

	assert.Equal(t, proposal.Source, p.Source)
	assert.Equal(t, proposal.DepositNonce, p.DepositNonce)
	assert.Equal(t, proposal.ResourceId, p.ResourceId)
	assert.Equal(t, proposal.Data, p.Data)

	assert.Equal(t, proposal.Hash(), p.Hash())
}