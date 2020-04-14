package pbft

import (
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
)

type Dispatcher struct {
	acceptVotes         map[common.Hash]*ProposalVote
	rejectedVotes       map[common.Hash]*ProposalVote
}

func (d *Dispatcher) ProcessVote(vote *ProposalVote) error {
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
		acceptVotes: make(map[common.Hash]*ProposalVote),
		rejectedVotes: make(map[common.Hash]*ProposalVote),
	}
}