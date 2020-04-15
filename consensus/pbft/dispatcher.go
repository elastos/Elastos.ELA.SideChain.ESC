package pbft

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

type Dispatcher struct {
	acceptVotes         map[common.Uint256]*payload.DPOSProposalVote
	rejectedVotes       map[common.Uint256]*payload.DPOSProposalVote
}

func (d *Dispatcher) ProcessVote(vote *payload.DPOSProposalVote) error {
	if err := CheckVote(vote); err != nil {
		return err
	}

	if vote.Accept {
		d.acceptVotes[vote.Hash()] = vote
	} else {
		d.rejectedVotes[vote.Hash()] = vote
	}

	return nil
}

func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		acceptVotes: make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes: make(map[common.Uint256]*payload.DPOSProposalVote),
	}
}