package pbft

import (
	"bytes"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	dmsg "github.com/elastos/Elastos.ELA.SideChain.ETH/dpos/msg"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

func (p *Pbft) StartProposal(block *types.Block) error {
	log.Info("StartProposal", "block hash:", block.Hash().String())

	hash, err := elacom.Uint256FromBytes(block.Hash().Bytes())
	if err != nil {
		return err
	}
	proposal, err := dpos.StartProposal(p.account, *hash)
	if err != nil {
		log.Error("Start proposal error", "err", err)
		return err
	}
	m := &msg.Proposal{
		Proposal: *proposal,
	}
	log.Info("[StartProposal] send proposal message finished", "proposal", msg.GetMessageHash(m))
	p.network.BroadcastMessage(m)

	if err, _ := p.dispatcher.ProcessProposal(proposal); err != nil {
		log.Error("ProcessProposal error", "err", err)
	}

	return nil
}

func (p *Pbft) BroadPreBlock(block *types.Block) error {
	log.Info("BroadPreBlock,", "block Height:", block.NumberU64())
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
	fmt.Println("OnPing", id, height)
}

func (p *Pbft) OnPong(id peer.PID, height uint32) {
	fmt.Println("OnPong", id, height)
}

func (p *Pbft) OnBlock(id peer.PID, block *dmsg.BlockMsg) {
	fmt.Println("-----On PreBlock received------:::")
	b := &types.Block{}

	err := b.DecodeRLP(rlp.NewStream(bytes.NewBuffer(block.GetData()), 0))
	if err != nil {
		panic("OnBlock Decode Block Msg error:" + err.Error())
	}
	p.blockPool.AppendDposBlock(b)

	if _, ok := p.requestedBlocks[b.Hash()]; ok {
		delete(p.requestedBlocks, b.Hash())
	}
}

func (p *Pbft) OnInv(id peer.PID, blockHash elacom.Uint256) {
	if !p.dispatcher.GetProducers().IsProducers(p.account.PublicKeyBytes()) {
		return
	}
	if p.blockPool.HasBlock(blockHash) {
		return
	}
	hash := common.BytesToHash(blockHash.Bytes())
	if _, ok := p.requestedBlocks[hash]; ok {
		return
	}

	log.Info("[ProcessInv] send getblock:", blockHash.String())
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

func (p *Pbft) OnRequestConsensus(id peer.PID, height uint32) {
	fmt.Println("OnRequestConsensus")
}

func (p *Pbft) OnResponseConsensus(id peer.PID, status *msg.ConsensusStatus) {
	fmt.Println("OnResponseConsensus")
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
	if _, ok := p.blockPool.GetBlock(proposal.BlockHash); !ok {
		log.Info("not have preBlock, request it", "hash:", proposal.BlockHash.String())
		p.OnInv(id, proposal.BlockHash)
		return
	}
	var voteMsg *msg.Vote
	err, isSendReject := p.dispatcher.ProcessProposal(proposal)
	if err != nil {
		log.Error("ProcessProposal error", "err", err)
		if isSendReject {
			voteMsg = p.dispatcher.RejectProposal(proposal, p.account)
		}
	} else {
		voteMsg = p.dispatcher.AcceptProposal(proposal, p.account)
	}
	if voteMsg != nil {
		p.network.BroadcastMessage(voteMsg)
	}
}

func (p *Pbft) OnVoteAccepted(id peer.PID, vote *payload.DPOSProposalVote) {
	log.Info("OnVoteAccepted:", "hash:", vote.Hash().String())
	currentProposal, ok := p.tryGetCurrentProposal(id, vote)
	if !ok {
		log.Info("not have proposal, get it and push vote into pending vote")
		p.dispatcher.AddPendingVote(vote)
	} else if currentProposal.IsEqual(vote.ProposalHash) {
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
}

func (p *Pbft) OnBadNetwork() {
	fmt.Println("OnBadNetwork")
}

func (p *Pbft) OnRecover() {
	fmt.Println("OnRecover")
}

func (p *Pbft) OnRecoverTimeout() {
	fmt.Println("OnRecoverTimeout")
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