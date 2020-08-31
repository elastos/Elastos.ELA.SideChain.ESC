// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"bytes"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestConfirmMsg(t *testing.T) {
	proposal := payload.DPOSProposal{
		Sponsor: randomUint168().Bytes(),
		BlockHash: *randomUint256(),
		ViewOffset: 1,
		Sign: []byte{1,2,3},
	}
	hash := proposal.Hash()
	votes :=  make([]payload.DPOSProposalVote,  0)
	for i := 0; i < 4; i++ {
		vote := payload.DPOSProposalVote{
			ProposalHash: hash,
			Signer: randomUint168().Bytes(),
			Accept: true,
			Sign: []byte{1,2,3},
		}
		votes = append(votes, vote)

	}
	confirm := &payload.Confirm{Proposal: proposal, Votes: votes}

	msg := NewConfirmMsg(confirm, 3)
	msgBuffer := new(bytes.Buffer)
	err := msg.Serialize(msgBuffer)
	assert.NoError(t, err)


	msg2 := ConfirmMsg{}
	err = msg2.Deserialize(msgBuffer)
	assert.NoError(t, err)

	assert.Equal(t, msg.Confirm.Proposal.Hash(), msg2.Confirm.Proposal.Hash())
	assert.Equal(t, msg.Confirm.Proposal.BlockHash, msg2.Confirm.Proposal.BlockHash)
	assert.Equal(t, msg.Confirm.Proposal.Sponsor, msg2.Confirm.Proposal.Sponsor)
	assert.Equal(t, msg.Confirm.Proposal.ViewOffset, msg2.Confirm.Proposal.ViewOffset)
	assert.Equal(t, msg.Confirm.Proposal.Sign, msg2.Confirm.Proposal.Sign)
	assert.Equal(t, msg.Height, msg2.Height)

	for i, v := range msg2.Confirm.Votes {
		assert.Equal(t, v.ProposalHash, msg.Confirm.Votes[i].ProposalHash)
		assert.Equal(t, v.Signer, msg.Confirm.Votes[i].Signer)
		assert.Equal(t, v.Accept, msg.Confirm.Votes[i].Accept)
		assert.Equal(t, v.Sign, msg.Confirm.Votes[i].Sign)
		assert.Equal(t, v.Hash(), msg.Confirm.Votes[i].Hash())
	}

}