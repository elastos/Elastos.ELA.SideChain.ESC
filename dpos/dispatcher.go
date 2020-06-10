package dpos

import (
	"errors"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

type Dispatcher struct {
	acceptVotes   map[common.Uint256]*payload.DPOSProposalVote
	rejectedVotes map[common.Uint256]*payload.DPOSProposalVote
	pendingVotes  map[common.Uint256]*payload.DPOSProposalVote

	processingProposal *payload.DPOSProposal
	producers          *Producers

	proposalConfirmCh chan *payload.Confirm
}

func (d *Dispatcher) ProcessProposal(proposal *payload.DPOSProposal) (err error, isSendReject bool) {
	Info("[ProcessProposal] start")
	defer Info("[ProcessProposal] end")

	if d.processingProposal != nil {
		return errors.New("processingProposal is not nil"), false
	}

	if d.processingProposal != nil && d.processingProposal.Hash().IsEqual(proposal.Hash()) {
		return errors.New("already processing this proposal:" + proposal.Hash().String()), false
	}

	if !d.producers.IsProducers(proposal.Sponsor) {
		return errors.New("current signer is not producer"), true
	}

	if !d.producers.IsOnduty(proposal.Sponsor) {
		return errors.New("current signer is not onDuty"), true
	}

	err = CheckProposal(proposal)
	if err != nil {
		return err, true
	}

	d.setProcessingProposal(proposal)
	return nil, false
}

func (d *Dispatcher) setProcessingProposal(p *payload.DPOSProposal) (finished bool) {
	d.processingProposal = p

	for _, v := range d.pendingVotes {
		if v.ProposalHash.IsEqual(p.Hash()) {
			_, finished, _ := d.ProcessVote(v)
			if finished {
				return finished
			}
		}
	}
	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	return false
}

func (d *Dispatcher) AddPendingVote(v *payload.DPOSProposalVote) {
	d.pendingVotes[v.Hash()] = v
}

func (d *Dispatcher) ProcessVote(vote *payload.DPOSProposalVote) (succeed bool, finished bool, err error) {
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
			Info("Collect majority signs. Proposal confirmed.")
			confirm := d.createConfirm()
			d.proposalConfirmCh <- confirm
			Info("Block confirmed.")
			return true, true, nil
		}
	} else {
		d.rejectedVotes[vote.Hash()] = vote
		if d.producers.IsMajorityRejected(len(d.rejectedVotes)) {
			Info("Collect majority signs, reject proposal")
			d.FinishedProposal()
			return true, false, nil
		}
	}

	return true, false, nil
}

func (d *Dispatcher) FinishedProposal() {
	d.processingProposal = nil
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.rejectedVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.producers.ChangeView()
}

func (d *Dispatcher) alreadyExistVote(v *payload.DPOSProposalVote) bool {
	_, ok := d.acceptVotes[v.Hash()]
	if ok {
		Info("[alreadyExistVote]: ", v.Signer, "already in the AcceptVotes!")
		return true
	}

	_, ok = d.rejectedVotes[v.Hash()]
	if ok {
		Info("[alreadyExistVote]: ", v.Signer, "already in the RejectedVotes!")
		return true
	}

	return false
}

func (d *Dispatcher) AcceptProposal(proposal *payload.DPOSProposal, ac account.Account) *msg.Vote {
	if d.setProcessingProposal(proposal) {
		return nil
	}
	hash := proposal.Hash()

	vote, err := StartVote(&hash, true, ac)
	if err != nil {
		Error("StartVote error", "err", err)
		return nil
	}
	return &msg.Vote{Command: msg.CmdAcceptVote, Vote: *vote}
}


func (d *Dispatcher) RejectProposal(proposal *payload.DPOSProposal, ac account.Account) *msg.Vote {
	if d.setProcessingProposal(proposal) {
		return nil
	}
	hash := proposal.Hash()
	vote, err := StartVote(&hash, false, ac)
	if err != nil {
		Error("StartVote error", "err", err)
		return nil
	}
	return &msg.Vote{Command: msg.CmdRejectVote, Vote: *vote}
}

func (d *Dispatcher) createConfirm() *payload.Confirm {
	confirm := &payload.Confirm{
		Proposal: *d.processingProposal,
		Votes:    make([]payload.DPOSProposalVote, 0),
	}
	for _, vote := range d.acceptVotes {
		confirm.Votes = append(confirm.Votes, *vote)
	}

	return confirm
}

func (d *Dispatcher) GetProducers() *Producers {
	return d.producers
}

func (p *Dispatcher) GetProcessingProposal() *payload.DPOSProposal {
	return p.processingProposal
}

func (d *Dispatcher) GetNeedConnectProducers() []peer.PID {
	peers := make([]peer.PID, len(d.producers.producers))
	for i, p := range d.producers.producers {
		var pid peer.PID
		copy(pid[:], p)
		peers[i] = pid
	}
	return peers
}

func NewDispatcher(producers [][]byte, confirmCh chan *payload.Confirm) *Dispatcher {
	return &Dispatcher{
		acceptVotes:       make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes:     make(map[common.Uint256]*payload.DPOSProposalVote),
		pendingVotes:      make(map[common.Uint256]*payload.DPOSProposalVote),
		producers:         NewProducers(producers),
		proposalConfirmCh: confirmCh,
	}
}
