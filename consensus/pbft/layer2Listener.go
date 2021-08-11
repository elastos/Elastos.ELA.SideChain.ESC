package pbft

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	dpeer "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
	elap2p "github.com/elastos/Elastos.ELA/p2p"
)

func (p *Pbft) SendMsgProposal(proposalMsg elap2p.Message) {
	if p.network == nil {
		panic("direct network is nil")
	}
	p.BroadMessage(proposalMsg)
}

func (p *Pbft) SendMsgToPeer(proposalMsg elap2p.Message, pid dpeer.PID) {
	if p.network != nil {
		p.network.SendMessageToPeer(pid, proposalMsg)
	}
}

func (p *Pbft) SignData(data []byte) []byte {
	return p.account.Sign(data)
}

func (p *Pbft) GetProducer() []byte {
	if p.account != nil {
		return p.account.PublicKeyBytes()
	}
	return nil
}

func (p *Pbft) GetTotalProducerCount() int {
	return len(p.dispatcher.GetConsensusView().GetProducers())
}

func (p *Pbft) OnLayer2Msg(id dpeer.PID, c elap2p.Message) {
	switch c.CMD() {
	case dpos_msg.CmdDepositproposal:
		msg, ok := c.(*dpos_msg.DepositProposalMsg)
		if ok {
			events.Notify(dpos_msg.ETOnProposal, msg)
		}
	case dpos_msg.CmdBatchProposal:
		msg, ok := c.(*dpos_msg.BatchMsg)
		if ok {
			msg.PID = id
			events.Notify(dpos_msg.ETOnProposal, msg)
		}
	case dpos_msg.CmdFeedbackBatch:
		msg, ok := c.(*dpos_msg.FeedbackBatchMsg)
		if ok {
			events.Notify(dpos_msg.ETOnProposal, msg)
		}
	}
}