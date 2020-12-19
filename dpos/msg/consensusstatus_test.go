// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"bytes"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
)

func TestConsensusStatus(t *testing.T) {
	votes :=  make([]payload.DPOSProposalVote,  0)
	for i := 0; i < 4; i++ {
		vote := payload.DPOSProposalVote{
			ProposalHash: *randomUint256(),
			Signer: randomUint168().Bytes(),
			Accept: true,
			Sign: []byte{1,2,3},
		}
		votes = append(votes, vote)

	}

	pendingProposals :=  make([]payload.DPOSProposal,  0)
	for i := 0; i < 4; i++ {
		proposal := payload.DPOSProposal{
			Sponsor: []byte{1,2,3},
			BlockHash: *randomUint256(),
			ViewOffset: rand.Uint32(),
			Sign: []byte{1,2,3},
		}
		pendingProposals = append(pendingProposals, proposal)

	}

	msg := &ConsensusStatus{
		ConsensusStatus: rand.Uint32(),
		ViewOffset: rand.Uint32(),
		ViewStartTime: time.Now(),
		AcceptVotes: votes,
		RejectedVotes: votes,
		PendingProposals: pendingProposals,
		PendingVotes: votes,
		WorkingHeight: rand.Uint64(),
	}

	msgBuffer := new(bytes.Buffer)
	err := msg.Serialize(msgBuffer)
	assert.NoError(t, err)

	msg2 := &ConsensusStatus{}
	err = msg2.Deserialize(msgBuffer)
	assert.NoError(t, err)
	assert.Equal(t, msg.WorkingHeight, msg2.WorkingHeight)
	assert.Equal(t, msg.PendingVotes, msg2.PendingVotes)
	assert.Equal(t, msg.PendingProposals, msg2.PendingProposals)
	assert.Equal(t, msg.ViewOffset, msg2.ViewOffset)
	assert.Equal(t, msg.RejectedVotes, msg2.RejectedVotes)
	assert.Equal(t, msg.AcceptVotes, msg2.AcceptVotes)
}