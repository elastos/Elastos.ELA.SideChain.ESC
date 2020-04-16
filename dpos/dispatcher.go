package dpos

import (
	"errors"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

type Dispatcher struct {
	acceptVotes         map[common.Uint256]*payload.DPOSProposalVote
	rejectedVotes       map[common.Uint256]*payload.DPOSProposalVote

	processingProposal  *payload.DPOSProposal
	producers           *Producers
}

func (d *Dispatcher) ProcessProposal(proposal *payload.DPOSProposal) error {
	Info("[ProcessProposal] start")
	defer Info("[ProcessProposal] end")

	if d.processingProposal != nil {
		return  errors.New("processingProposal is not nil")
	}

	if d.processingProposal != nil && d.processingProposal.Hash().IsEqual(proposal.Hash()) {
		return errors.New("already processing this proposal:" + proposal.Hash().String())
	}

	if !d.producers.IsProducers(proposal.Sponsor) {
		return errors.New("current signer is not producer")
	}

	if !d.producers.IsOnduty(proposal.Sponsor) {
		return errors.New("current signer is not producer")
	}

	err := CheckProposal(proposal)
	if err != nil {
		return err
	}

	d.processingProposal = proposal
	return nil
}


func (d *Dispatcher) ProcessVote(vote *payload.DPOSProposalVote) (succeed bool, finished bool, err error)  {
	Info("[ProcessVote] start")
	defer Info("[ProcessVote] end")

	if d.processingProposal == nil {
		err = errors.New("not proposal to process vote")
		return false, false, err
	}

	if !vote.ProposalHash.IsEqual(d.processingProposal.Hash()) {
		err = errors.New("vote proposal is not processing proposal")
		return false, false, err
	}

	if d.alreadyExistVote(vote) {
		err = errors.New("alreadyExistVote")
		return false, false, err
	}

	if !d.producers.IsProducers(vote.Signer) {
		err = errors.New("current signer is not producer")
		return false, false, err
	}

	if err := CheckVote(vote); err != nil {
		return false, false, err
	}

	if vote.Accept {
		d.acceptVotes[vote.Hash()] = vote
		if d.producers.IsMajorityAgree(len(d.acceptVotes)) {
			Info("Collect majority signs, finish proposal.")
			//todo finished this proposal
			return true, true, nil
		}
	} else {
		d.rejectedVotes[vote.Hash()] = vote
		if d.producers.IsMajorityRejected(len(d.rejectedVotes)) {
			Info("Collect majority signs, reject proposal")
			//todo change view to reconsensus
			return true, false, nil
		}
	}

	return true, false, nil
}

func (d *Dispatcher) alreadyExistVote(v *payload.DPOSProposalVote) bool {
	_, ok := d.acceptVotes[v.Hash()]
	if ok {
		return true
	}

	_, ok = d.rejectedVotes[v.Hash()]
	if ok {
		return true
	}

	return false
}

func NewDispatcher(producers [][]byte) *Dispatcher {
	return &Dispatcher{
		acceptVotes:   make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes: make(map[common.Uint256]*payload.DPOSProposalVote),
		producers:     NewProducers(producers),
	}
}