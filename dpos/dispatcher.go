// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"sync"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

type Dispatcher struct {
	acceptVotes         map[common.Uint256]*payload.DPOSProposalVote
	rejectedVotes       map[common.Uint256]*payload.DPOSProposalVote
	pendingVotes        map[common.Uint256]*payload.DPOSProposalVote
	precociousProposals map[common.Uint256]*payload.DPOSProposal

	processingProposal *payload.DPOSProposal
	consensusView      *ConsensusView
	timeSource         dtime.MedianTimeSource

	onConfirm func(confirm *payload.Confirm) error
	unConfirm func(confirm *payload.Confirm) error

	proposalProcessFinished bool
	finishedHeight          uint64
	finishedBlockSealHash   common.Uint256
	finishedProposal        common.Uint256

	mu sync.RWMutex
}

func (d *Dispatcher) ProcessProposal(id peer.PID, proposal *payload.DPOSProposal) (err error, isSendReject bool, handled bool) {
	Info("[ProcessProposal] start ", proposal.Hash().String())
	defer Info("[ProcessProposal] end", proposal.Hash().String())
	self := bytes.Equal(id[:], proposal.Sponsor)

	if d.GetConsensusView().GetViewOffset() != proposal.ViewOffset {
		Info("have different view offset")
		if proposal.ViewOffset > d.GetConsensusView().GetViewOffset() {
			d.precociousProposals[proposal.Hash()] = proposal
		}
		return errors.New("have different view offset"), false, !self
	}

	if !d.consensusView.ProducerIsOnDuty(proposal.Sponsor) {
		return errors.New("current signer is not onDuty"), false, !self
	}

	if d.processingProposal != nil && d.processingProposal.Hash().IsEqual(proposal.Hash()) {
		return errors.New("already processing this proposal:" + proposal.Hash().String()), false, true
	}

	if !d.consensusView.IsProducers(proposal.Sponsor) {
		return errors.New("current signer is not producer"), true, true
	}
	err = CheckProposal(proposal)
	if err != nil {
		return err, true, true
	}

	d.setProcessingProposal(proposal)
	return nil, false, true
}

func (d *Dispatcher) GetProposalProcessFinished() bool {
	return d.proposalProcessFinished
}

func (d *Dispatcher) GetFinishedHeight() uint64 {
	return d.finishedHeight
}

func (d *Dispatcher) SetProposalProcessFinished() {
	d.proposalProcessFinished = true
}

func (d *Dispatcher) GetFinishedBlockSealHash() common.Uint256 {
	return d.finishedBlockSealHash
}

func (d *Dispatcher) GetFinishedProposal() common.Uint256 {
	return d.finishedProposal
}

func (d *Dispatcher) setProcessingProposal(p *payload.DPOSProposal) (finished bool) {
	d.processingProposal = p
	log.Info("setProcessingProposal start")
	defer log.Info("setProcessingProposal end")
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
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pendingVotes[v.Hash()] = v
}

func (d *Dispatcher) ProcessVote(vote *payload.DPOSProposalVote) (succeed bool, finished bool, err error) {
	Info("[ProcessVote] start")
	defer Info("[ProcessVote] end")
	d.mu.Lock()
	defer d.mu.Unlock()
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

func (d *Dispatcher) FinishedProposal(height uint64, sealHash common.Uint256,
	headerTime uint64) {
	Info("FinishedProposal")
	d.finishedHeight = height
	d.finishedBlockSealHash = sealHash
	if d.processingProposal != nil {
		d.finishedProposal = d.processingProposal.Hash()
	}

	d.consensusView.SetReady()
	d.CleanProposals(false)
	d.consensusView.ChangeView(d.timeSource.AdjustedTime(), true, headerTime)
}
func (d *Dispatcher) CleanProposals(changeView bool) {
	Info("Clean proposals")
	d.processingProposal = nil
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.rejectedVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	d.proposalProcessFinished = false
	if !changeView {
		d.precociousProposals = make(map[common.Uint256]*payload.DPOSProposal)
	} else {
		// clear pending proposals less than current view offset
		currentOffset := d.consensusView.GetViewOffset()
		for k, v := range d.precociousProposals {
			if v.ViewOffset < currentOffset {
				delete(d.precociousProposals, k)
			}
		}
	}
}

func (d *Dispatcher) UpdatePrecociousProposals() *payload.DPOSProposal {
	for k, v := range d.precociousProposals {
		if d.consensusView.IsRunning() &&
			v.ViewOffset == d.consensusView.GetViewOffset() {
			delete(d.precociousProposals, k)
			return v
		}
	}
	return nil
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

func (d *Dispatcher) GetProcessingProposal() *payload.DPOSProposal {
	return d.processingProposal
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

func (d *Dispatcher) ResetView(parentTime uint64) {
	d.consensusView.ResetView(d.timeSource.AdjustedTime(), parentTime)
}

func (d *Dispatcher) GetConsensusView() *ConsensusView {
	return d.consensusView
}

func (d *Dispatcher) HelpToRecoverAbnormal(id peer.PID, height uint64, currentHeight uint64) *msg.ConsensusStatus {
	Info("[HelpToRecoverAbnormal] peer id:", common.BytesToHexString(id[:]))

	if height > currentHeight {
		Error("Requesting height greater than current processing height")
		return nil
	}
	status := &msg.ConsensusStatus{}
	status.ConsensusStatus = d.consensusView.consensusStatus
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
	if medianTime != 0 {
		offset, offsetTime := d.consensusView.calculateOffsetTime(status.ViewStartTime, d.timeSource.AdjustedTime())
		status.ViewOffset += offset
		status.ViewStartTime = d.timeSource.AdjustedTime().Add(-offsetTime)
	}
	d.RecoverFromConsensusStatus(status)
}

func (d *Dispatcher) RecoverFromConsensusStatus(status *msg.ConsensusStatus) error {
	d.consensusView.consensusStatus = status.ConsensusStatus
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
	d.consensusView.ResetView(status.ViewStartTime, uint64(status.ViewStartTime.Unix()))
	d.consensusView.isDposOnDuty = d.consensusView.ProducerIsOnDuty(d.consensusView.publicKey)
	Info("\n\n\n\n \n\n\n\n -------[End RecoverFromConsensusStatus]-------- startTime", d.consensusView.GetViewStartTime())
	d.consensusView.DumpInfo()
	Info("\n\n\n\n \n\n\n\n")
	return nil
}

func (d *Dispatcher) GetNowTime() time.Time {
	return d.timeSource.AdjustedTime()
}

func NewDispatcher(producers [][]byte, onConfirm func(confirm *payload.Confirm) error,
	unConfirm func(confirm *payload.Confirm) error, tolerance time.Duration, publicKey []byte,
	medianTime dtime.MedianTimeSource, viewListener ViewListener) *Dispatcher {
	return &Dispatcher{
		acceptVotes:         make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes:       make(map[common.Uint256]*payload.DPOSProposalVote),
		pendingVotes:        make(map[common.Uint256]*payload.DPOSProposalVote),
		precociousProposals: make(map[common.Uint256]*payload.DPOSProposal),
		consensusView:       NewConsensusView(tolerance, publicKey, NewProducers(producers), viewListener),
		onConfirm:           onConfirm,
		unConfirm:           unConfirm,
		timeSource:          medianTime,
	}
}
