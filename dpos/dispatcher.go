// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"

	dmsg "github.com/elastos/Elastos.ELA.SideChain.ESC/dpos/msg"
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

	mu         sync.RWMutex
	proposalMu sync.RWMutex

	resetViewRequests map[string]struct{} // sponsors
	resetViewMu       sync.RWMutex
}

func (d *Dispatcher) ProcessProposal(id peer.PID, proposal *payload.DPOSProposal) (err error, isSendReject bool, handled bool) {
	Info("[ProcessProposal] start ", proposal.Hash().String(), "peerID", id.String(), "Sponsor", common.BytesToHexString(proposal.Sponsor))
	defer Info("[ProcessProposal] end", proposal.Hash().String())
	self := bytes.Equal(id[:], proposal.Sponsor)
	Info("is self", self)
	if d.GetConsensusView().GetViewOffset() != proposal.ViewOffset {
		Info("have different view offset")
		if proposal.ViewOffset > d.GetConsensusView().GetViewOffset() {
			d.precociousProposals[proposal.Hash()] = proposal
		}
		return errors.New("have different view offset"), false, false
	}

	if !d.consensusView.ProducerIsOnDuty(proposal.Sponsor) {
		return errors.New("current signer is not onDuty"), false, !self
	}

	if d.processingProposal != nil && d.processingProposal.Hash().IsEqual(proposal.Hash()) {
		return errors.New("already processing this proposal:" + proposal.Hash().String()), false, true
	}

	if !d.consensusView.IsProducers(proposal.Sponsor) {
		str := fmt.Sprintf("%s proposal signer is not producer", common.BytesToHexString(proposal.Sponsor))
		return errors.New(str), true, true
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
	Info("setProcessingProposal start")
	d.proposalMu.Lock()
	d.processingProposal = p
	d.proposalMu.Unlock()
	d.mu.Lock()
	defer func() {
		d.mu.Unlock()
		Info("setProcessingProposal end")
	}()
	for _, v := range d.pendingVotes {
		if v.ProposalHash.IsEqual(p.Hash()) {
			_, finished, _ := d.processVote(v)
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
	return d.processVote(vote)
}

func (d *Dispatcher) processVote(vote *payload.DPOSProposalVote) (succeed bool, finished bool, err error) {
	proposal := d.GetProcessingProposal()
	if proposal == nil {
		err = errors.New("not proposal to process vote")
		return false, false, err
	}

	if !vote.ProposalHash.IsEqual(proposal.Hash()) {
		err = errors.New("vote proposal is not processing proposal")
		return false, false, err
	}

	if d.alreadyExistVote(vote) {
		err = errors.New("alreadyExistVote")
		return false, false, err
	}

	if !d.consensusView.IsProducers(vote.Signer) {
		str := fmt.Sprintf("%s vote signer is not producer", common.BytesToHexString(vote.Signer))
		err = errors.New(str)
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
			if confirm != nil {
				err = d.onConfirm(confirm)
			}
			Info("Block confirmed.", "error", err)
			return true, true, err
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
	if height <= d.finishedHeight {
		Warn("FinishedProposal received fork block", "height", height)
		return
	}
	d.finishedHeight = height
	d.finishedBlockSealHash = sealHash
	if d.processingProposal != nil {
		d.finishedProposal = d.processingProposal.Hash()
	}

	d.consensusView.SetReady()
	d.CleanProposals(false)
	d.consensusView.UpdateDutyIndex(height)
	d.consensusView.ChangeView(d.timeSource.AdjustedTime(), true, headerTime)
	d.resetViewMu.Lock()
	d.resetViewRequests = make(map[string]struct{}, 0)
	d.resetViewMu.Unlock()
}

func (d *Dispatcher) ResetConsensus(height uint64) {
	Info("[resetConsensus] start", "d.consensusView.IsRunning()", d.consensusView.IsRunning())
	defer Info("[resetConsensus] end")

	if d.consensusView.IsRunning() {
		Info("[resetConsensus] reset view")
		d.consensusView.SetReady()
		d.CleanProposals(false)
		d.consensusView.resetViewOffset()
		d.consensusView.UpdateDutyIndex(height)
		d.consensusView.ChangeView(d.timeSource.AdjustedTime(), true, uint64(d.timeSource.AdjustedTime().Unix()))
	}
	d.resetViewMu.Lock()
	d.resetViewRequests = make(map[string]struct{}, 0)
	d.resetViewMu.Unlock()
}

func (d *Dispatcher) OnResponseResetViewReceived(msg *msg.ResetView) error {
	signer := msg.Sponsor
	sign := msg.Sign

	data := new(bytes.Buffer)
	if err := msg.SerializeUnsigned(
		data); err != nil {
		return err
	}

	pk, err := crypto.DecodePoint(signer)
	if err != nil {
		return err
	}

	if err := crypto.Verify(*pk, data.Bytes(), sign); err != nil {
		Errorf("invalid message signature:", *msg)
		return err
	}
	d.RecordViewRequest(signer)
	return nil
}

func (d *Dispatcher) GetResetViewReqCount() int {
	d.resetViewMu.Lock()
	defer d.resetViewMu.Unlock()
	return len(d.resetViewRequests)
}

func (d *Dispatcher) ResetViewRequestIsContain(sponsor []byte) bool {
	d.resetViewMu.Lock()
	defer d.resetViewMu.Unlock()
	if d.resetViewRequests == nil {
		return false
	}
	_, ok := d.resetViewRequests[common.BytesToHexString(sponsor)]
	return ok
}

func (d *Dispatcher) RecordViewRequest(sponsor []byte) {
	d.resetViewMu.Lock()
	defer d.resetViewMu.Unlock()
	if d.resetViewRequests == nil {
		d.resetViewRequests = make(map[string]struct{}, 0)
	}
	d.resetViewRequests[common.BytesToHexString(sponsor)] = struct{}{}
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

func (d *Dispatcher) ResetAcceptVotes() {
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
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
		Info("[alreadyExistVote]: ", common.BytesToHexString(v.Signer), "already in the AcceptVotes!")
		return true
	}

	_, ok = d.rejectedVotes[v.Hash()]
	if ok {
		Info("[alreadyExistVote]: ", common.BytesToHexString(v.Signer), "already in the RejectedVotes!")
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
	if d.processingProposal == nil {
		Warn("processingProposal is nil, can't create confirm")
		return nil
	}
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
	d.proposalMu.Lock()
	defer d.proposalMu.Unlock()
	return d.processingProposal
}

func (d *Dispatcher) GetNextNeedConnectArbiters() []peer.PID {
	return d.consensusView.GetNextNeedConnectArbiters()
}

func (d *Dispatcher) GetCurrentNeedConnectArbiters() []peer.PID {
	return d.consensusView.getCurrentNeedConnectArbiters()
}

func (d *Dispatcher) OnChangeView() {
	d.consensusView.TryChangeView(d.timeSource.AdjustedTime())
}

func (d *Dispatcher) ResetView(parentTime uint64) {
	d.consensusView.ResetView(parentTime)
}

func (d *Dispatcher) GetConsensusView() *ConsensusView {
	return d.consensusView
}

func (d *Dispatcher) HelpToRecoverAbnormal(id peer.PID, height uint64, currentHeight uint64) *dmsg.ConsensusStatus {
	Info("[HelpToRecoverAbnormal]  peer id:", common.BytesToHexString(id[:]))

	if height > currentHeight {
		Warn("Requesting height greater than current processing height")
		return nil
	}
	if len(d.consensusView.GetProducers()) <= 0 {
		Warn("Requesting chain is pow state")
		return nil
	}
	status := &dmsg.ConsensusStatus{}
	status.ConsensusStatus = d.consensusView.consensusStatus
	status.ViewOffset = d.consensusView.viewOffset
	status.ViewStartTime = d.consensusView.GetViewStartTime()

	status.AcceptVotes = make([]payload.DPOSProposalVote, 0, len(d.acceptVotes))
	//for _, v := range d.acceptVotes {
	//	status.AcceptVotes = append(status.AcceptVotes, *v)
	//}

	status.RejectedVotes = make([]payload.DPOSProposalVote, 0, len(d.rejectedVotes))
	//for _, v := range d.rejectedVotes {
	//	status.RejectedVotes = append(status.RejectedVotes, *v)
	//}

	status.PendingProposals = make([]payload.DPOSProposal, 0, 1)
	//if d.processingProposal != nil {
	//	status.PendingProposals = append(status.PendingProposals, *d.processingProposal)
	//}

	status.PendingVotes = make([]payload.DPOSProposalVote, 0, len(d.pendingVotes))
	//for _, v := range d.pendingVotes {
	//	status.PendingVotes = append(status.PendingVotes, *v)
	//}
	status.WorkingHeight = d.consensusView.producers.workingHeight
	return status

}

func (d *Dispatcher) RecoverAbnormal(status *dmsg.ConsensusStatus, medianTime int64) {
	if status == nil {
		return
	}
	status.ViewStartTime = dtime.Int64ToTime(medianTime)
	if medianTime != 0 {
		offset, offsetTime := d.consensusView.calculateOffsetTime(status.ViewStartTime, d.timeSource.AdjustedTime())
		status.ViewOffset += offset
		status.ViewStartTime = d.timeSource.AdjustedTime().Add(-offsetTime)
	}
	d.RecoverFromConsensusStatus(status)
}

func (d *Dispatcher) RecoverFromConsensusStatus(status *dmsg.ConsensusStatus) error {
	d.consensusView.consensusStatus = status.ConsensusStatus
	d.acceptVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	//for _, v := range status.AcceptVotes {
	//	vote := v
	//	d.acceptVotes[v.Hash()] = &vote
	//}

	d.rejectedVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	//for _, v := range status.RejectedVotes {
	//	vote := v
	//	d.rejectedVotes[v.Hash()] = &vote
	//}
	d.processingProposal = nil
	//for _, v := range status.PendingProposals {
	//	d.setProcessingProposal(&v)
	//}

	d.pendingVotes = make(map[common.Uint256]*payload.DPOSProposalVote)
	//for _, v := range status.PendingVotes {
	//	vote := v
	//	d.pendingVotes[v.Hash()] = &vote
	//}

	d.consensusView.viewOffset = status.ViewOffset
	d.consensusView.ResetView(uint64(status.ViewStartTime.Unix()))
	d.consensusView.isDposOnDuty = d.consensusView.ProducerIsOnDuty(d.consensusView.publicKey)
	d.consensusView.SetWorkingHeight(status.WorkingHeight)
	if d.finishedHeight > 0 {
		d.consensusView.UpdateDutyIndex(d.finishedHeight)
	}
	Info("\n\n\n\n \n\n\n\n -------[End RecoverFromConsensusStatus]-------- startTime", d.consensusView.GetViewStartTime(), "WorkingHeight", status.WorkingHeight, "dutyIndex", d.GetConsensusView().GetDutyIndex(), "d.finishedHeight", d.finishedHeight, "status.ViewOffset", status.ViewOffset)
	d.consensusView.DumpInfo()
	Info("\n\n\n\n \n\n\n\n")
	return nil
}

func (d *Dispatcher) GetNowTime() time.Time {
	return d.timeSource.AdjustedTime()
}

func NewDispatcher(producers [][]byte, onConfirm func(confirm *payload.Confirm) error,
	unConfirm func(confirm *payload.Confirm) error, tolerance time.Duration, publicKey []byte,
	medianTime dtime.MedianTimeSource, viewListener ViewListener, dposStartHeight uint64) *Dispatcher {
	return &Dispatcher{
		acceptVotes:         make(map[common.Uint256]*payload.DPOSProposalVote),
		rejectedVotes:       make(map[common.Uint256]*payload.DPOSProposalVote),
		pendingVotes:        make(map[common.Uint256]*payload.DPOSProposalVote),
		precociousProposals: make(map[common.Uint256]*payload.DPOSProposal),
		consensusView:       NewConsensusView(tolerance, publicKey, NewProducers(producers, dposStartHeight), viewListener),
		onConfirm:           onConfirm,
		unConfirm:           unConfirm,
		timeSource:          medianTime,
	}
}
