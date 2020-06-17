// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"errors"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

type Dispatcher struct {
	acceptVotes   map[common.Uint256]*payload.DPOSProposalVote
	rejectedVotes map[common.Uint256]*payload.DPOSProposalVote
	pendingVotes  map[common.Uint256]*payload.DPOSProposalVote

	processingProposal *payload.DPOSProposal
	consensusView      *ConsensusView
	timeSource         dtime.MedianTimeSource

	onConfirm func(confirm *payload.Confirm) error
	unConfirm func(confirm *payload.Confirm) error
}

func (d *Dispatcher) ProcessProposal(proposal *payload.DPOSProposal) (err error, isSendReject bool) {
	Info("[ProcessProposal] start ", proposal.Hash().String())
	defer Info("[ProcessProposal] end", proposal.Hash().String())

	if d.processingProposal != nil {
		return errors.New("processingProposal is not nil"), false
	}

	if d.processingProposal != nil && d.processingProposal.Hash().IsEqual(proposal.Hash()) {
		return errors.New("already processing this proposal:" + proposal.Hash().String()), false
	}

	if !d.consensusView.IsProducers(proposal.Sponsor) {
		return errors.New("current signer is not producer"), true
	}

	if !d.consensusView.ProducerIsOnDuty(proposal.Sponsor) {
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

	if !d.consensusView.IsProducers(vote.Signer) {
		err = errors.New("current signer is not producer")
		return false, false, err
	}

	if err := CheckVote(vote); err != nil {
		return false, false, err
	}

	if vote.Accept {
		d.acceptVotes[vote.Hash()] = vote
		Info("acceptVotes count:", len(d.acceptVotes))
		if d.consensusView.IsMajorityAgree(len(d.acceptVotes)) {
			Info("Collect majority signs. Proposal confirmed.")
			confirm := d.createConfirm()
			d.onConfirm(confirm)
			Info("Block confirmed.")
			return true, true, nil
		}
	} else {
		d.rejectedVotes[vote.Hash()] = vote
		Info("rejectedVotes count:", len(d.rejectedVotes))
		if d.consensusView.IsMajorityRejected(len(d.rejectedVotes)) {
			Info("Collect majority signs, reject proposal")
			d.unConfirm(d.createUnConfirm())
			return true, false, nil
		}
	}

	return true, false, nil
}

func (d *Dispatcher) FinishedProposal() {
	d.CleanProposals()
	d.consensusView.ChangeView(d.timeSource.AdjustedTime(), true)
}

func (d *Dispatcher) CleanProposals() {
	Info("Clean proposals")
	d.processingProposal = nil
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.rejectedVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
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

func (d *Dispatcher) createUnConfirm() *payload.Confirm {
	confirm := &payload.Confirm{
		Proposal: *d.processingProposal,
		Votes:    make([]payload.DPOSProposalVote, 0),
	}
	for _, vote := range d.rejectedVotes {
		confirm.Votes = append(confirm.Votes, *vote)
	}

	return confirm
}

func (d *Dispatcher) IsProducer(account []byte) bool {
	return d.consensusView.IsProducers(account)
}

func (d *Dispatcher) ProducerIsOnDuty() bool {
	return d.consensusView.IsOnduty()
}

func (p *Dispatcher) GetProcessingProposal() *payload.DPOSProposal {
	return p.processingProposal
}

func (d *Dispatcher) GetNeedConnectProducers() []peer.PID {
	peers := make([]peer.PID, len(d.consensusView.producers.producers))
	for i, p := range d.consensusView.producers.producers {
		var pid peer.PID
		copy(pid[:], p)
		peers[i] = pid
	}
	return peers
}

func (d *Dispatcher) OnChangeView() {
	d.consensusView.TryChangeView(d.timeSource.AdjustedTime())
}

func (d *Dispatcher) ResetView() {
	d.consensusView.ResetView(d.timeSource.AdjustedTime())
}

func (d *Dispatcher) GetConsensusView() *ConsensusView {
	return d.consensusView
}

func (d *Dispatcher) HelpToRecoverAbnormal(id peer.PID, height uint64, currentHeight uint64) *msg.ConsensusStatus {
	Info("\n \n \n \n[HelpToRecoverAbnormal] peer id:", common.BytesToHexString(id[:]))

	if height > currentHeight {
		Error("Requesting height greater than current processing height")
		return nil
	}
	status := &msg.ConsensusStatus{}
	status.ViewOffset = d.consensusView.viewOffset
	status.ViewStartTime = d.consensusView.GetViewStartTime()

	status.AcceptVotes = make([]payload.DPOSProposalVote, 0, len(d.acceptVotes))
	for _, v := range d.acceptVotes {
		status.AcceptVotes = append(status.AcceptVotes, *v)
	}

	status.RejectedVotes = make([]payload.DPOSProposalVote, 0, len(d.rejectedVotes))
	for _, v := range d.rejectedVotes {
		status.RejectedVotes = append(status.RejectedVotes, *v)
	}

	status.PendingProposals = make([]payload.DPOSProposal, 0, 1)
	if d.processingProposal != nil {
		status.PendingProposals = append(status.PendingProposals, *d.processingProposal)
	}

	status.PendingVotes = make([]payload.DPOSProposalVote, 0, len(d.pendingVotes))
	for _, v := range d.pendingVotes {
		status.PendingVotes = append(status.PendingVotes, *v)
	}
	return status

}

func (d *Dispatcher) RecoverAbnormal(status *msg.ConsensusStatus, medianTime int64) {
	status.ViewStartTime = dtime.Int64ToTime(medianTime)
	offset, offsetTime := d.consensusView.calculateOffsetTime(status.ViewStartTime, d.timeSource.AdjustedTime())
	status.ViewOffset += offset
	status.ViewStartTime = d.timeSource.AdjustedTime().Add(-offsetTime)

	d.RecoverFromConsensusStatus(status)
}

func (d *Dispatcher) RecoverFromConsensusStatus(status *msg.ConsensusStatus) error {
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	for _, v := range status.AcceptVotes {
		vote := v
		d.acceptVotes[v.Hash()] = &vote
	}

	d.rejectedVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	for _, v := range status.RejectedVotes {
		vote := v
		d.rejectedVotes[v.Hash()] = &vote
	}
	d.processingProposal = nil
	for _, v := range status.PendingProposals {
		d.setProcessingProposal(&v)
	}

	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	for _, v := range status.PendingVotes {
		vote := v
		d.pendingVotes[v.Hash()] = &vote
	}

	d.consensusView.viewOffset = status.ViewOffset
	d.consensusView.ResetView(status.ViewStartTime)
	d.consensusView.isDposOnDuty = d.consensusView.ProducerIsOnDuty(d.consensusView.publicKey)
	Info("\n\n\n\n \n\n\n\n -------[End RecoverFromConsensusStatus]-------- startTime", d.consensusView.GetViewStartTime())
	d.consensusView.DumpInfo()
	Info("\n\n\n\n \n\n\n\n")
	return nil
}

func NewDispatcher(producers [][]byte, onConfirm func(confirm *payload.Confirm) error,
	unConfirm func(confirm *payload.Confirm) error, tolerance time.Duration, publicKey []byte,
	medianTime dtime.MedianTimeSource, viewListener ViewListener) *Dispatcher {
	return &Dispatcher{
		acceptVotes:   make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes: make(map[common.Uint256]*payload.DPOSProposalVote),
		pendingVotes:  make(map[common.Uint256]*payload.DPOSProposalVote),
		consensusView: NewConsensusView(tolerance, publicKey, NewProducers(producers), viewListener),
		onConfirm:     onConfirm,
		unConfirm:     unConfirm,
		timeSource:    medianTime,
	}
}
