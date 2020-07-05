package pbft

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	dmsg "github.com/elastos/Elastos.ELA.SideChain.ETH/dpos/msg"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
	"github.com/elastos/Elastos.ELA/events"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
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
	m := &msg.Proposal{
		Proposal: *proposal,
	}
	log.Info("[StartProposal] send proposal message", "proposal", msg.GetMessageHash(m))
	p.network.BroadcastMessage(m)

	if err, _ := p.dispatcher.ProcessProposal(proposal); err != nil {
		log.Error("ProcessProposal error", "err", err)
	}

	return nil
}

func (p *Pbft) AnnounceDAddr() bool {
	if p.account == nil {
		log.Error("is not a super node")
		return false
	}
	producers := p.dispatcher.GetNeedConnectProducers()
	log.Info("Announce DAddr ", "Producers:", producers)
	events.Notify(events.ETDirectPeersChanged, producers)
	return true
}

func (p *Pbft) BroadPreBlock(block *types.Block) error {
	sealHash := p.SealHash(block.Header())
	log.Info("BroadPreBlock,", "block Height:", block.NumberU64(), "hash:", sealHash.String())
	buffer := bytes.NewBuffer([]byte{})
	err := block.EncodeRLP(buffer)
	if err != nil {
		return err
	}
	msg := dmsg.NewBlockMsg(buffer.Bytes())
	p.network.BroadcastMessage(msg)
	p.blockPool.AppendDposBlock(block)
	return nil
}

func (p *Pbft) RequestAbnormalRecovering() {
	height := p.chain.CurrentHeader().Height()
	msgItem := &dmsg.RequestConsensus{Height: height}
	log.Info("[RequestAbnormalRecovering]", "height", height)
	p.network.BroadcastMessage(msgItem)
}

func (p *Pbft) tryGetCurrentProposal(id peer.PID, v *payload.DPOSProposalVote) (elacom.Uint256, bool) {
	currentProposal := p.dispatcher.GetProcessingProposal()
	if currentProposal == nil {
		requestProposal := &msg.RequestProposal{ProposalHash: v.ProposalHash}
		go p.network.SendMessageToPeer(id, requestProposal)
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
	log.Info("-----On PreBlock received------")
	b := &types.Block{}

	err := b.DecodeRLP(rlp.NewStream(bytes.NewBuffer(block.GetData()), 0))
	if err != nil {
		panic("OnBlock Decode Block Msg error:" + err.Error())
	}
	sealHash := p.SealHash(b.Header())
	log.Info("-----OnBlock received------", "blockHash:", sealHash.String(), "height:", b.NumberU64())
	err = p.blockPool.AppendDposBlock(b)
	if err == consensus.ErrUnknownAncestor {
		log.Info("Append Future blocks", "height:", b.NumberU64())
		p.blockPool.AppendFutureBlock(b)
	}

	if _, ok := p.requestedBlocks[sealHash]; ok {
		delete(p.requestedBlocks, sealHash)
	}
}

func (p *Pbft) AccessFutureBlock(parent *types.Block) {
	if p.blockPool.HandleParentBlock(parent) {
		log.Info("----[Send RequestProposal]-----")
		requestProposal := &msg.RequestProposal{ProposalHash: elacom.EmptyHash}
		go p.network.BroadcastMessage(requestProposal)
	}
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
		msg := &msg.ResponseConsensus{Consensus: *status}
		go p.network.SendMessageToPeer(id, msg)
	}
}

func (p *Pbft) OnResponseConsensus(id peer.PID, status *msg.ConsensusStatus) {
	log.Info("---------[OnResponseConsensus]------------")
	if !p.IsProducer() {
		return
	}
	log.Info("[OnResponseConsensus] status:", "status", *status)
	if  !p.recoverStarted {
		return
	}
	if _, ok := p.statusMap[status.ViewOffset]; !ok {
		p.statusMap[status.ViewOffset] = make(map[string]*msg.ConsensusStatus)
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
	if !p.dispatcher.GetConsensusView().IsRunning() {
		log.Info("consensus is not running")
		return
	}
	hash := common.BytesToHash(proposal.BlockHash.Bytes())
	if b := p.chain.GetBlockByHash(hash); b != nil {
		log.Info("allready confirm proposal drop it", "hash:", p.SealHash(b.Header()), "height", b.NumberU64())
		return
	}

	if _, ok := p.blockPool.GetBlock(proposal.BlockHash); !ok {
		log.Info("not have preBlock, request it", "hash:", proposal.BlockHash.String())
		p.OnInv(id, proposal.BlockHash)
		return
	}
	var voteMsg *msg.Vote
	err, isSendReject := p.dispatcher.ProcessProposal(proposal)
	if err != nil {
		log.Error("Process Proposal error", "err", err)
		if isSendReject {
			voteMsg = p.dispatcher.RejectProposal(proposal, p.account)
		} else if p.dispatcher.GetConsensusView().GetViewOffset() != proposal.ViewOffset {
			log.Info("[OnProposalReceived] has minority not handled" +
				" proposals, need recover")
			if p.dispatcher.GetConsensusView().HasArbitersMinorityCount(len(p.network.GetActivePeers())) {
				if p.recoverAbnormalState() {
					log.Info("[OnProposalReceived] recover start")
				} else {
					log.Error("[OnProposalReceived] has no active peers recover failed")
				}
			} else {
				log.Info("active peers is short:", len(p.network.GetActivePeers()))
			}
		}

	} else {
		voteMsg = p.dispatcher.AcceptProposal(proposal, p.account)
	}
	if voteMsg != nil {
		p.network.BroadcastMessage(voteMsg)
	}
}

func (p *Pbft) OnVoteAccepted(id peer.PID, vote *payload.DPOSProposalVote) {
	if !p.dispatcher.GetConsensusView().IsRunning() {
		return
	}
	if vote.Accept == true {
		log.Info("OnVoteAccepted:", "hash:", vote.Hash().String())
	}
	if _, ok := p.blockPool.GetConfirm(vote.ProposalHash); ok {
		log.Info("all ready confim proposal, no need vote, drop")
		return
	}
	currentProposal, ok := p.tryGetCurrentProposal(id, vote)
	if !ok {
		log.Info("not have proposal, get it and push vote into pending vote")
		p.dispatcher.AddPendingVote(vote)
	} else if currentProposal.IsEqual(vote.ProposalHash) {
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
	if p.account == nil || !p.dispatcher.IsProducer(p.account.PublicKeyBytes()){
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
		p.statusMap = make(map[uint32]map[string]*msg.ConsensusStatus)
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
	var status *msg.ConsensusStatus
	startTimes := make([]int64, 0)
	for _, v := range p.statusMap[maxCountMaxViewOffset] {
		if status == nil {
			status = v
		}
		startTimes = append(startTimes, v.ViewStartTime.UnixNano())
	}
	sort.Slice(startTimes, func(i, j int) bool {
		return startTimes[i] < startTimes[j]
	})
	medianTime := medianOf(startTimes)
	p.dispatcher.RecoverAbnormal(status, medianTime)
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

func (p *Pbft) OnBlockReceived(b *dmsg.BlockMsg, confirmed bool) {
	fmt.Println("OnBlockReceived")
}

func (p *Pbft) OnConfirmReceived(c *payload.Confirm, height uint32) {
	fmt.Println("OnConfirmReceived")
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