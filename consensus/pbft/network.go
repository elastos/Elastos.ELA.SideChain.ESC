package pbft

import (
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	dmsg "github.com/elastos/Elastos.ELA.SideChain.ETH/dpos/msg"

	elacom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
)

func (p *Pbft) StartProposal(block *types.Block) error {
	fmt.Println("StartProposal")

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

	if err := p.dispatcher.ProcessProposal(proposal); err != nil {
		log.Error("ProcessProposal error", "err", err)
	}

	return nil
}

func (p *Pbft) OnPing(id peer.PID, height uint32) {
	fmt.Println("OnPing", id, height)
}

func (p *Pbft) OnPong(id peer.PID, height uint32) {
	fmt.Println("OnPong", id, height)
}

func (p *Pbft) OnBlock(id peer.PID, block *dmsg.BlockMsg) {
	fmt.Println("OnBlock")
}

func (p *Pbft) OnInv(id peer.PID, blockHash elacom.Uint256) {
	fmt.Println("OnInv")
}

func (p *Pbft) OnGetBlock(id peer.PID, blockHash elacom.Uint256) {
	fmt.Println("OnGetBlock")
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
	fmt.Println("OnRequestProposal")
}

func (p *Pbft) OnIllegalProposalReceived(id peer.PID, proposals *payload.DPOSIllegalProposals) {
	fmt.Println("OnIllegalProposalReceived")
}

func (p *Pbft) OnIllegalVotesReceived(id peer.PID, votes *payload.DPOSIllegalVotes) {
	fmt.Println("OnIllegalVotesReceived")
}

func (p *Pbft) OnProposalReceived(id peer.PID, proposal *payload.DPOSProposal) {
	fmt.Println("OnProposalReceived")

	err := p.dispatcher.ProcessProposal(proposal)
	if err != nil {
		log.Error("ProcessProposal error", "err", err)
		return
	}
	phash := proposal.Hash()
	vote, err := dpos.StartVote(&phash, true, p.account)
	if err != nil {
		log.Error("StartVote error", "err", err)
		return
	}

	voteMsg := &msg.Vote{Command: msg.CmdAcceptVote, Vote: *vote}

	p.network.BroadcastMessage(voteMsg)

	// fixme
	p.dispatcher.FinishedProposal()
}

func (p *Pbft) OnVoteAccepted(id peer.PID, vote *payload.DPOSProposalVote) {
	fmt.Println("OnVoteAccepted")

	_, _, err := p.dispatcher.ProcessVote(vote)
	if err != nil {
		log.Error("ProcessVote error", "err", err)
	}
}

func (p *Pbft) OnVoteRejected(id peer.PID, vote *payload.DPOSProposalVote) {
	fmt.Println("OnVoteRejected")
}

func (p *Pbft) OnChangeView() {
	fmt.Println("OnChangeView")
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
