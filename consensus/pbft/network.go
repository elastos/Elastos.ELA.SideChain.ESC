// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pbft

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	dmsg "github.com/elastos/Elastos.ELA.SideChain.ESC/dpos/msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/smallcrosstx"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/withdrawfailedtx"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/p2p"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
	elap2p "github.com/elastos/Elastos.ELA/p2p"
)

func (p *Pbft) StartProposal(block *types.Block) error {
	sealHash := p.SealHash(block.Header())
	log.Info("StartProposal", "block hash:", sealHash.String())

	hash, err := elacom.Uint256FromBytes(sealHash.Bytes())
	if err != nil {
		return err
	}
	proposal, err := dpos.StartProposal(p.account, *hash, p.dispatcher.GetConsensusView().GetViewOffset())
	if err != nil {
		log.Error("Start proposal error", "err", err)
		return err
	}

	var id peer.PID
	copy(id[:], p.account.PublicKeyBytes()[:])
	if err, _, _ := p.dispatcher.ProcessProposal(id, proposal); err != nil {
		log.Error("ProcessProposal error", "err", err)
	}

	m := &msg.Proposal{
		Proposal: *proposal,
	}
	log.Info("[StartProposal] send proposal message", "proposal", msg.GetMessageHash(m))
	p.BroadMessage(m)
	// Broadcast vote
	voteMsg := p.dispatcher.AcceptProposal(proposal, p.account)
	if voteMsg != nil {
		go p.OnVoteAccepted(id, &voteMsg.Vote)
		p.BroadMessage(voteMsg)
	}
	return nil
}

func (p *Pbft) BroadMessage(msg elap2p.Message) {
	peers := p.network.DumpPeersInfo()

	for _, peer := range peers {
		pid := peer.PID[:]
		producer := p.dispatcher.GetConsensusView().IsProducers(pid)
		if producer == false {
			continue
		}
		p.network.SendMessageToPeer(peer.PID, msg)
	}
}

func (p *Pbft) BroadMessageToPeers(msg elap2p.Message, peers [][]byte) {
	for _, pbk := range peers {
		pid := peer.PID{}
		copy(pid[:], pbk)
		p.network.SendMessageToPeer(pid, msg)
	}
}

type peerInfo struct {
	OwnerPublicKey string `json:"ownerpublickey"`
	NodePublicKey  string `json:"nodepublickey"`
	IP             string `json:"ip"`
	ConnState      string `json:"connstate"`
}

func (p *Pbft) GetAtbiterPeersInfo() []peerInfo {
	if p.account == nil {
		return nil
	}

	peers := p.network.DumpPeersInfo()

	result := make([]peerInfo, 0)
	for _, peer := range peers {
		pid := peer.PID[:]
		producer := p.dispatcher.GetConsensusView().IsProducers(pid)
		if producer == false {
			continue
		}
		result = append(result, peerInfo{
			NodePublicKey: common.Bytes2Hex(pid),
			IP:            peer.Addr,
			ConnState:     peer.State.String(),
		})
	}
	return result
}

func (p *Pbft) GetAllArbiterPeersInfo() []*p2p.PeerInfo {
	if p.account == nil {
		return nil
	}
	return p.network.DumpPeersInfo()
}

func (p *Pbft) AnnounceDAddr() bool {
	if p.account == nil {
		log.Error("is not a super node")
		return false
	}
	currents := p.dispatcher.GetCurrentNeedConnectArbiters()
	nextArbites := p.dispatcher.GetNextNeedConnectArbiters()
	log.Info("Announce DAddr ", "currents:", currents, "nextArbites", nextArbites)
	events.Notify(events.ETDirectPeersChangedV2,
		&peer.PeersInfo{CurrentPeers: currents, NextPeers: nextArbites})
	return true
}

func (p *Pbft) UpdateCurrentProducers(producers [][]byte, totalCount int, spvHeight uint64) {
	p.dispatcher.GetConsensusView().UpdateProducers(producers, totalCount, spvHeight)
}

func (p *Pbft) GetCurrentProducers() [][]byte {
	if p.dispatcher != nil {
		return p.dispatcher.GetConsensusView().GetProducers()
	}
	return [][]byte{}
}

func (p *Pbft) IsProducerByAccount(account []byte) bool {
	if p.dispatcher != nil {
		return p.dispatcher.IsProducer(account)
	}
	return false
}

func (p *Pbft) BroadBlockMsg(block *types.Block) error {
	sealHash := p.SealHash(block.Header())
	log.Info("BroadPreBlock,", "block Height:", block.NumberU64(), "hash:", sealHash.String())
	buffer := bytes.NewBuffer([]byte{})
	err := block.EncodeRLP(buffer)
	if err != nil {
		return err
	}
	msg := dmsg.NewBlockMsg(buffer.Bytes())
	p.BroadMessage(msg)
	p.blockPool.AppendDposBlock(block)
	return nil
}

func (p *Pbft) RequestAbnormalRecovering() {
	height := p.chain.CurrentHeader().Height()
	msgItem := &dmsg.RequestConsensus{Height: height}
	log.Info("[RequestAbnormalRecovering]", "height", height)
	p.BroadMessage(msgItem)
}

func (p *Pbft) tryGetCurrentProposal(id peer.PID, v *payload.DPOSProposalVote) (elacom.Uint256, bool) {
	currentProposal := p.dispatcher.GetProcessingProposal()
	if currentProposal == nil {
		if v.ProposalHash.IsEqual(p.dispatcher.GetFinishedProposal()) {
			log.Info("received finished proposal vote")
			return elacom.EmptyHash, true
		}
		if _, ok := p.requestedProposals[v.ProposalHash]; !ok {
			requestProposal := &msg.RequestProposal{ProposalHash: v.ProposalHash}
			go p.network.SendMessageToPeer(id, requestProposal)
			p.requestedProposals[v.ProposalHash] = struct{}{}
		}
		return elacom.EmptyHash, false
	}
	return currentProposal.Hash(), true
}

func (p *Pbft) OnPing(id peer.PID, height uint32) {
	//fmt.Println("OnPing", id, height)
}

func (p *Pbft) OnPong(id peer.PID, height uint32) {
	//fmt.Println("OnPong", id, height)
}

func (p *Pbft) OnBlock(id peer.PID, block *dmsg.BlockMsg) {
	log.Info("-----OnBlock received------")
	b := &types.Block{}

	err := b.DecodeRLP(rlp.NewStream(bytes.NewBuffer(block.GetData()), 0))
	if err != nil {
		panic("OnBlock Decode Block Msg error:" + err.Error())
	}
	if len(b.Extra()) > extraVanity {
		p.OnBlockReceived(id, block, true)
		return
	}

	if b.NumberU64() <= p.chain.CurrentHeader().Number.Uint64() ||
		b.NumberU64() <= p.dispatcher.GetFinishedHeight() {
		p.blockPool.AddBadBlock(b)
		log.Warn("old height block coming  blockchain.Height", "chain height", p.chain.CurrentHeader().Number.Uint64(), "b.Height", b.NumberU64(), "finishedHeight", p.dispatcher.GetFinishedHeight())
		return
	}
	sealHash := p.SealHash(b.Header())
	log.Info("-----On PreBlock received------", "blockHash:", sealHash.String(), "height:", b.NumberU64())
	err = p.blockPool.AppendDposBlock(b)
	if err == consensus.ErrUnknownAncestor {
		log.Info("Append Future blocks", "height:", b.NumberU64())
		p.blockPool.AppendFutureBlock(b)
	}

	hash, err := elacom.Uint256FromBytes(sealHash.Bytes())
	if err == nil {
		if c, ok := p.blockPool.GetConfirm(*hash); ok {
			p.OnConfirmReceived(id, c, b.GetHeight())
		}
	}

	if _, ok := p.requestedBlocks[sealHash]; ok {
		delete(p.requestedBlocks, sealHash)
	}
}

func (p *Pbft) AccessFutureBlock(parent *types.Block) {
	if p.blockPool.HandleParentBlock(parent) {
		log.Info("----[Send RequestProposal]-----")
		requestProposal := &msg.RequestProposal{ProposalHash: elacom.EmptyHash}
		go p.BroadMessage(requestProposal)
	}
}

func (p *Pbft) OnInsertBlock(block *types.Block) bool {
	if p.dispatcher == nil {
		return false
	}
	dutyIndex := p.dispatcher.GetConsensusView().GetDutyIndex()
	isWorkingHeight := spv.SpvIsWorkingHeight()
	log.Info("[OnInsertBlock]", "dutyIndex", dutyIndex, "isWorkingHeight", isWorkingHeight)
	if dutyIndex == 0 && isWorkingHeight {
		curProducers := p.dispatcher.GetConsensusView().GetProducers()
		isSame := p.dispatcher.GetConsensusView().IsSameProducers(curProducers)
		if !isSame {
			p.dispatcher.GetConsensusView().ChangeCurrentProducers(block.NumberU64()+1, spv.GetSpvHeight())
			go p.AnnounceDAddr()
			go p.Recover()
			p.dispatcher.GetConsensusView().DumpInfo()
		} else {
			log.Info("For the same batch of producers, no need to change current producers")
		}
		spv.InitNextTurnDposInfo()
		return !isSame
	} else if block.Nonce() > 0 {
		//used to sync completed to consensus
		spvHeight := spv.GetSpvHeight()
		if spvHeight < block.Nonce() {
			spvHeight = block.Nonce()
		}
		producers, totalCount, err := spv.GetProducers(spvHeight)
		if err != nil {
			log.Error("OnInsertBlock error", "GetProducers", err, "spvHeight", spvHeight)
			return false
		}
		isBackword := p.dispatcher.GetConsensusView().GetSpvHeight() < block.Nonce()
		isCurrent := p.IsCurrentProducers(producers)
		log.Info("current producers spvHeight", "height", p.dispatcher.GetConsensusView().GetSpvHeight(), "block.Nonce()", block.Nonce(), "isBackword", isBackword, "isCurrent", isCurrent)
		if isBackword && !isCurrent {
			p.dispatcher.GetConsensusView().UpdateProducers(producers, totalCount, spvHeight)
			go p.AnnounceDAddr()
			go p.Recover()
			return true
		}
	}
	return false
}

func (p *Pbft) GetSelfDutyIndex() int {
	if p.account == nil {
		return -1
	}
	return p.dispatcher.GetConsensusView().ProducerIndex(p.account.PublicKeyBytes())
}

func (p *Pbft) OnInv(id peer.PID, blockHash elacom.Uint256) {
	if !p.dispatcher.IsProducer(p.account.PublicKeyBytes()) {
		return
	}
	if p.blockPool.HasBlock(blockHash) {
		return
	}
	hash := common.BytesToHash(blockHash.Bytes())
	if _, ok := p.requestedBlocks[hash]; ok {
		return
	}

	log.Info("[ProcessInv] send getblock:", "hash", blockHash.String())
	p.limitMap(p.requestedBlocks, maxRequestedBlocks)
	p.requestedBlocks[hash] = struct{}{}
	go p.network.SendMessageToPeer(id, msg.NewGetBlock(blockHash))
}

func (p *Pbft) OnGetBlock(id peer.PID, blockHash elacom.Uint256) {
	if block, ok := p.blockPool.GetBlock(blockHash); ok {
		if b, suc := block.(*types.Block); suc {
			buffer := bytes.NewBuffer([]byte{})
			err := b.EncodeRLP(buffer)
			if err != nil {
				log.Error("[OnGetBlock] Encode Block Error")
			}
			log.Info("Send block to peer", "peer:", id, "height:", block.GetHeight())
			go p.network.SendMessageToPeer(id, dmsg.NewBlockMsg(buffer.Bytes()))
		} else {
			log.Error("block is not ethereum block")
		}
	}
}

func (p *Pbft) OnGetBlocks(id peer.PID, startBlockHeight, endBlockHeight uint32) {
	fmt.Println("OnGetBlocks")
}

func (p *Pbft) OnResponseBlocks(id peer.PID, blockConfirms []*dmsg.BlockMsg) {
	fmt.Println("OnResponseBlocks")
}

func (p *Pbft) OnRequestConsensus(id peer.PID, height uint64) {
	log.Info("------- [OnRequestConsensus] -------")
	if !p.IsProducer() {
		log.Warn("------- not a producer -------")
		return
	}

	status := p.dispatcher.HelpToRecoverAbnormal(id, height, p.chain.CurrentHeader().Height())
	if status != nil {
		msg := &dmsg.ResponseConsensus{Consensus: *status}
		go p.network.SendMessageToPeer(id, msg)
	}
}

func (p *Pbft) OnResponseConsensus(id peer.PID, status *dmsg.ConsensusStatus) {
	log.Info("---------[OnResponseConsensus]------------", "pid", id.String())
	if !p.IsProducer() {
		return
	}
	if !p.recoverStarted {
		return
	}
	if _, ok := p.statusMap[status.ViewOffset]; !ok {
		p.statusMap[status.ViewOffset] = make(map[string]*dmsg.ConsensusStatus)
	}
	p.statusMap[status.ViewOffset][common.Bytes2Hex(id[:])] = status
}

func (p *Pbft) OnRequestProposal(id peer.PID, hash elacom.Uint256) {
	currentProposal := p.dispatcher.GetProcessingProposal()
	if currentProposal != nil {
		responseProposal := &msg.Proposal{Proposal: *currentProposal}
		go p.network.SendMessageToPeer(id, responseProposal)
	}
}

func (p *Pbft) OnIllegalProposalReceived(id peer.PID, proposals *payload.DPOSIllegalProposals) {
	fmt.Println("OnIllegalProposalReceived")
}

func (p *Pbft) OnIllegalVotesReceived(id peer.PID, votes *payload.DPOSIllegalVotes) {
	fmt.Println("OnIllegalVotesReceived")
}

func (p *Pbft) OnProposalReceived(id peer.PID, proposal *payload.DPOSProposal) {
	log.Info("OnProposalReceived", "hash:", proposal.Hash().String())
	if _, ok := p.requestedProposals[proposal.Hash()]; ok {
		delete(p.requestedProposals, proposal.Hash())
	}
	if p.dispatcher.GetProcessingProposal() != nil && p.dispatcher.GetProcessingProposal().Hash().IsEqual(proposal.Hash()) {
		log.Info("is processing this proposal")
		return
	}
	if !p.dispatcher.GetConsensusView().IsRunning() {
		log.Info("consensus is not running")
		return
	}
	p.dispatcher.OnChangeView()

	if proposal.BlockHash.IsEqual(p.dispatcher.GetFinishedBlockSealHash()) {
		log.Info("already processed block")
		return
	}

	isBadProposal := p.blockPool.IsBadBlockProposal(proposal)
	if _, ok := p.blockPool.GetBlock(proposal.BlockHash); !ok && !isBadProposal {
		if p.blockPool.IsFutureBlock(proposal.BlockHash) {
			log.Info("future propsal, wait syncing block")
			return
		}
		log.Info("not have preBlock, request it", "hash:", proposal.BlockHash.String())
		p.OnInv(id, proposal.BlockHash)
		return
	}
	var voteMsg *msg.Vote
	err, isSendReject, handled := p.dispatcher.ProcessProposal(id, proposal)
	if err != nil {
		log.Error("Process Proposal error", "err", err)
		if isSendReject {
			voteMsg = p.dispatcher.RejectProposal(proposal, p.account)
		} else if !handled {
			pubKey := common.Bytes2Hex(id[:])
			p.notHandledProposal[pubKey] = struct{}{}
			count := len(p.notHandledProposal)
			log.Info("[OnProposalReceived] not handled", "count", count)
			if p.dispatcher.GetConsensusView().HasArbitersMinorityCount(count) {
				log.Info("[OnProposalReceived] has minority not handled" +
					" proposals, need recover")
				if p.recoverAbnormalState() {
					log.Info("[OnProposalReceived] recover start")
				} else {
					log.Error("[OnProposalReceived] has no active peers recover failed")
				}
			}
		}

	} else if isBadProposal {
		log.Info("bad proposal reject")
		voteMsg = p.dispatcher.RejectProposal(proposal, p.account)
	} else {
		voteMsg = p.dispatcher.AcceptProposal(proposal, p.account)
	}

	if handled {
		log.Info("[OnProposalReceived]handled reset notHandledProposal")
		p.notHandledProposal = make(map[string]struct{})
	}
	if voteMsg != nil && !p.dispatcher.GetProposalProcessFinished() {
		p.BroadMessage(voteMsg)
		p.dispatcher.SetProposalProcessFinished()
	}
}

func (p *Pbft) OnVoteAccepted(id peer.PID, vote *payload.DPOSProposalVote) {
	if !p.IsProducer() {
		return
	}
	if !p.dispatcher.GetConsensusView().IsRunning() {
		return
	}
	if vote.Accept == true {
		log.Info("OnVoteAccepted:", "hash:", vote.Hash().String())
	}
	if p.dispatcher.GetFinishedProposal().IsEqual(vote.ProposalHash) {
		log.Info("all ready finished proposal, no need vote")
		return
	}
	if _, ok := p.blockPool.GetConfirm(vote.ProposalHash); ok {
		log.Info("all ready confim proposal, no need vote")
		return
	}
	currentProposal, ok := p.tryGetCurrentProposal(id, vote)
	if !ok {
		log.Info("not have proposal, get it and push vote into pending vote", "proposal", vote.ProposalHash.String())
		p.dispatcher.AddPendingVote(vote)
	} else if currentProposal.IsEqual(vote.ProposalHash) {
		if p.dispatcher.GetProcessingProposal() == nil {
			log.Info("GetProcessingProposal is nil")
			return
		}
		if _, ok := p.blockPool.GetConfirm(p.dispatcher.GetProcessingProposal().BlockHash); ok {
			log.Warn("Has Confirm proposal")
			return
		}
		_, _, err := p.dispatcher.ProcessVote(vote)
		if err != nil {
			log.Error("ProcessVote error", "err", err)
		}
	}
}

func (p *Pbft) OnVoteRejected(id peer.PID, vote *payload.DPOSProposalVote) {
	log.Info("OnVoteRejected", "hash:", vote.Hash().String())
	p.OnVoteAccepted(id, vote)
}

func (p *Pbft) OnChangeView() {
	p.dispatcher.OnChangeView()
}

func (p *Pbft) OnBadNetwork() {
	fmt.Println("OnBadNetwork")
}

func (p *Pbft) OnRecover() {
	if p.account == nil || !p.dispatcher.IsProducer(p.account.PublicKeyBytes()) {
		return
	}
	p.recoverAbnormalState()
}

func (p *Pbft) recoverAbnormalState() bool {
	if p.recoverStarted {
		return false
	}
	if producers := p.dispatcher.GetConsensusView().GetProducers(); len(producers) > 0 {
		if peers := p.network.GetActivePeers(); len(peers) == 0 {
			log.Error("[recoverAbnormalState] can not find active peer")
			return false
		}
		p.recoverStarted = true
		p.RequestAbnormalRecovering()
		go func() {
			<-time.NewTicker(time.Second * 2).C
			p.OnRecoverTimeout()
			p.isRecoved = true
			if p.chain.Engine() == p {
				p.StartMine()
			}
		}()
		return true
	}
	return false
}

func (p *Pbft) OnRecoverTimeout() {
	if p.recoverStarted == true {
		if len(p.statusMap) != 0 {
			p.DoRecover()
		}
		p.recoverStarted = false
		p.statusMap = make(map[uint32]map[string]*dmsg.ConsensusStatus)
	}
}

func (p *Pbft) DoRecover() {
	var maxCount int
	var maxCountMaxViewOffset uint32
	for k, v := range p.statusMap {
		if maxCount < len(v) {
			maxCount = len(v)
			maxCountMaxViewOffset = k
		} else if maxCount == len(v) && maxCountMaxViewOffset < k {
			maxCountMaxViewOffset = k
		}
	}
	var status *dmsg.ConsensusStatus
	startTimes := make([]int64, 0)
	for _, v := range p.statusMap[maxCountMaxViewOffset] {
		if status == nil {
			if v.ConsensusStatus == dpos.ConsensusReady {
				p.notHandledProposal = make(map[string]struct{})
				return
			}
			status = v
		}
		startTimes = append(startTimes, v.ViewStartTime.UnixNano())
	}
	sort.Slice(startTimes, func(i, j int) bool {
		return startTimes[i] < startTimes[j]
	})
	medianTime := medianOf(startTimes)
	p.dispatcher.RecoverAbnormal(status, medianTime)
	p.notHandledProposal = make(map[string]struct{})
}

func medianOf(nums []int64) int64 {
	l := len(nums)

	if l == 0 {
		return 0
	}

	if l%2 == 0 {
		return (nums[l/2] + nums[l/2-1]) / 2
	}

	return nums[l/2]
}

func (p *Pbft) OnBlockReceived(id peer.PID, b *dmsg.BlockMsg, confirmed bool) {
	log.Info("-------[OnBlockReceived]--------")
	if !confirmed {
		return
	}
	block := &types.Block{}

	err := block.DecodeRLP(rlp.NewStream(bytes.NewBuffer(b.GetData()), 0))
	if err != nil {
		panic("OnBlock Decode Block Msg error:" + err.Error())
	}

	delay := time.Unix(int64(block.Time()), 0).Sub(p.dispatcher.GetNowTime())
	log.Info("wait seal time", "delay", delay)
	time.Sleep(delay)

	parent := p.chain.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil { //ErrUnknownAncestor
		count := len(p.network.GetActivePeers())
		log.Warn("verify block error", "error", consensus.ErrUnknownAncestor, "activePeers", count)
		if !p.dispatcher.GetConsensusView().HasProducerMajorityCount(count) {
			go p.AnnounceDAddr()
		}
		return
	}

	blocks := types.Blocks{}
	blocks = append(blocks, block)
	log.Info("InsertChain", "height", block.GetHeight(), "block.NumberU64()-p.chain.CurrentBlock().NumberU64() ", block.Number().Cmp(p.chain.CurrentBlock().Number()), "currentBlock", p.chain.CurrentBlock().NumberU64())

	if block.Number().Cmp(p.chain.CurrentBlock().Number()) >= 0 && block.NumberU64()-p.chain.CurrentBlock().NumberU64() > 1 {
		log.Warn("is bigger than local number")
		return
	}
	if _, err := p.chain.InsertChain(blocks); err != nil {
		if p.OnInsertChainError != nil {
			p.OnInsertChainError(id, block, err)
		}
	}
}

func (p *Pbft) OnConfirmReceived(pid peer.PID, c *payload.Confirm, height uint64) {
	log.Info("OnConfirmReceived", "confirm", c.Proposal.Hash(), "height", height)
	defer log.Info("OnConfirmReceived end")

	if p.IsOnduty() {
		p.isSealOver = true
		go p.Recover()
		return
	}

	if height > p.chain.CurrentHeader().Number.Uint64()+1 {
		log.Info("is future confirm")
		return
	}

	if height <= p.dispatcher.GetFinishedHeight() {
		log.Info("already confirmed block")
		return
	}

	if _, hasConfirm := p.blockPool.GetConfirmByHeight(height); hasConfirm {
		log.Info("has confirmed block", "height", height)
		return
	}

	if _, ok := p.blockPool.GetBlock(c.Proposal.BlockHash); !ok {
		log.Info("not have preBlock, request it", "hash:", c.Proposal.BlockHash.String())
		p.OnInv(pid, c.Proposal.BlockHash)
		return
	}

	if _, ok := p.blockPool.GetConfirm(c.Proposal.BlockHash); !ok {
		p.dispatcher.ResetAcceptVotes()
		for _, vote := range c.Votes {
			p.dispatcher.ProcessVote(&vote)
		}
		return
	}
}

// limitMap is a helper function for maps that require a maximum limit by
// evicting a random transaction if adding a new value would cause it to
// overflow the maximum allowed.
func (p *Pbft) limitMap(m map[common.Hash]struct{}, limit int) {
	if len(m)+1 > limit {
		// Remove a random entry from the map.  For most compilers, Go's
		// range statement iterates starting at a random item although
		// that is not 100% guaranteed by the spec.  The iteration order
		// is not important here because an adversary would have to be
		// able to pull off preimage attacks on the hashing function in
		// order to target eviction of specific entries anyways.
		for hash := range m {
			delete(m, hash)
			return
		}
	}
}

func (p *Pbft) OnSmallCroTxReceived(id peer.PID, msg *dmsg.SmallCroTx) {
	list := p.GetCurrentProducers()
	total := p.dispatcher.GetConsensusView().GetTotalProducersCount()
	height := p.chain.CurrentBlock().GetHeight()
	smallcrosstx.OnReceivedSmallCroTxFromDirectNet(list, total, msg.GetSignature(), msg.GetRawTx(), height)
}

func (p *Pbft) OnFailedWithdrawTxReceived(id peer.PID, msg *dmsg.FailedWithdrawTx) {
	err := withdrawfailedtx.ReceivedFailedWithdrawTx(msg.GetHash(), msg.GetSignature())
	if err != nil {
		log.Error("ReceivedFailedWithdrawTx", "error", err)
	}
}
