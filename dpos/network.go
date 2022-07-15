// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	dmsg "github.com/elastos/Elastos.ELA.SideChain.ESC/dpos/msg"
	"net"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	dpeer "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	elap2p "github.com/elastos/Elastos.ELA/p2p"
)

type NetworkConfig struct {
	IPAddress      string
	Magic          uint32
	DefaultPort    uint16
	MaxNodePerHost uint32

	Account    account.Account
	MedianTime dtime.MedianTimeSource
	Listener   NetworkEventListener
	DataPath   string

	GetCurrentHeight   func(pid peer.PID) uint64
	ProposalDispatcher *Dispatcher
	PublicKey          []byte
	AnnounceAddr       func()
}

type DPOSNetwork interface {
	//Initialize(dnConfig DPOSNetworkConfig)

	Start()
	Stop() error

	SendMessageToPeer(id dpeer.PID, msg elap2p.Message) error
	BroadcastMessage(msg elap2p.Message)

	UpdatePeers(peers []dpeer.PID)
	GetActivePeers() []p2p.Peer
}

type StatusSyncEventListener interface {
	OnPing(id dpeer.PID, height uint32)
	OnPong(id dpeer.PID, height uint32)
	OnBlock(id dpeer.PID, block *dmsg.BlockMsg)
	OnInv(id dpeer.PID, blockHash common.Uint256)
	OnGetBlock(id dpeer.PID, blockHash common.Uint256)
	OnGetBlocks(id dpeer.PID, startBlockHeight, endBlockHeight uint32)
	OnResponseBlocks(id dpeer.PID, blockConfirms []*dmsg.BlockMsg)
	OnRequestConsensus(id dpeer.PID, height uint64)
	OnResponseConsensus(id dpeer.PID, status *dmsg.ConsensusStatus)
	OnRequestProposal(id dpeer.PID, hash common.Uint256)
	OnIllegalProposalReceived(id dpeer.PID, proposals *payload.DPOSIllegalProposals)
	OnIllegalVotesReceived(id dpeer.PID, votes *payload.DPOSIllegalVotes)
}

type NetworkEventListener interface {
	StatusSyncEventListener

	OnProposalReceived(id dpeer.PID, proposal *payload.DPOSProposal)
	OnVoteAccepted(id dpeer.PID, proposal *payload.DPOSProposalVote)
	OnVoteRejected(id dpeer.PID, proposal *payload.DPOSProposalVote)

	OnChangeView()
	OnBadNetwork()
	OnRecover()

	OnBlockReceived(id dpeer.PID, b *dmsg.BlockMsg, confirmed bool)
	OnConfirmReceived(id dpeer.PID, c *payload.Confirm, height uint64)

	OnSmallCroTxReceived(id dpeer.PID, c *dmsg.SmallCroTx)
	OnFailedWithdrawTxReceived(id dpeer.PID, c *dmsg.FailedWithdrawTx)

	OnLayer2Msg(id dpeer.PID, c elap2p.Message)
}

type messageItem struct {
	ID      peer.PID
	Message elap2p.Message
}

type Network struct {
	listener     NetworkEventListener
	publicKey    []byte
	announceAddr func()

	p2pServer    p2p.Server
	messageQueue chan *messageItem
	quit         chan bool

	badNetworkChan chan bool
	changeViewChan chan bool
	recoverChan    chan bool

	GetCurrentHeight func(pid peer.PID) uint64
}

func (n *Network) GetActivePeers() []p2p.Peer {
	return n.p2pServer.ConnectedPeers()
}

func (n *Network) notifyFlag(flag p2p.NotifyFlag) {
	if flag == p2p.NFBadNetwork {
		n.badNetworkChan <- true

		// Trigger announce address when network go bad.
		n.announceAddr()
	}
}

func (n *Network) Start() {
	n.p2pServer.Start()

	go func() {
	out:
		for {
			select {
			case msgItem := <-n.messageQueue:
				n.processMessage(msgItem)
			case <-n.changeViewChan:
				n.changeView()
			case <-n.badNetworkChan:
				n.badNetwork()
			case <-n.recoverChan:
				n.recover()
			case <-n.quit:
				break out
			}
		}
	}()
}

func (n *Network) Stop() error {
	n.quit <- true
	return n.p2pServer.Stop()
}

func (n *Network) PostChangeViewTask() {
	n.changeViewChan <- true
}

func (n *Network) PostRecoverTask() {
	n.recoverChan <- true
}

func (n *Network) processMessage(msgItem *messageItem) {
	m := msgItem.Message
	switch m.CMD() {
	case msg.CmdReceivedProposal:
		msgProposal, processed := m.(*msg.Proposal)
		if processed {
			n.listener.OnProposalReceived(msgItem.ID, &msgProposal.Proposal)
		}
	case msg.CmdAcceptVote:
		msgVote, processed := m.(*msg.Vote)
		if processed {
			n.listener.OnVoteAccepted(msgItem.ID, &msgVote.Vote)
		}
	case msg.CmdRejectVote:
		msgVote, processed := m.(*msg.Vote)
		if processed {
			n.listener.OnVoteRejected(msgItem.ID, &msgVote.Vote)
		}
	case msg.CmdPing:
		msgPing, processed := m.(*msg.Ping)
		if processed {
			n.listener.OnPing(msgItem.ID, uint32(msgPing.Nonce))
		}
	case msg.CmdPong:
		msgPong, processed := m.(*msg.Pong)
		if processed {
			n.listener.OnPong(msgItem.ID, uint32(msgPong.Nonce))
		}
	case elap2p.CmdBlock:
		blockMsg, processed := m.(*dmsg.BlockMsg)
		if processed {
			n.listener.OnBlock(msgItem.ID, blockMsg)
		}
	case msg.CmdInv:
		msgInv, processed := m.(*msg.Inventory)
		if processed {
			n.listener.OnInv(msgItem.ID, msgInv.BlockHash)
		}
	case msg.CmdGetBlock:
		msgGetBlock, processed := m.(*msg.GetBlock)
		if processed {
			n.listener.OnGetBlock(msgItem.ID, msgGetBlock.BlockHash)
		}
	case msg.CmdGetBlocks:
		msgGetBlocks, processed := m.(*msg.GetBlocks)
		if processed {
			n.listener.OnGetBlocks(msgItem.ID, msgGetBlocks.StartBlockHeight, msgGetBlocks.EndBlockHeight)
		}
	case msg.CmdResponseBlocks:
		//msgResponseBlocks, processed := m.(*dmsg.BlockMsg)
		//if processed {
		//n.listener.OnResponseBlocks(msgItem.ID, msgResponseBlocks)
		//}
	case msg.CmdRequestConsensus:
		msgRequestConsensus, processed := m.(*dmsg.RequestConsensus)
		if processed {
			n.listener.OnRequestConsensus(msgItem.ID, msgRequestConsensus.Height)
		}
	case msg.CmdResponseConsensus:
		msgResponseConsensus, processed := m.(*dmsg.ResponseConsensus)
		if processed {
			n.listener.OnResponseConsensus(msgItem.ID, &msgResponseConsensus.Consensus)
		}
	case msg.CmdRequestProposal:
		msgRequestProposal, processed := m.(*msg.RequestProposal)
		if processed {
			n.listener.OnRequestProposal(msgItem.ID, msgRequestProposal.ProposalHash)
		}
	case msg.CmdIllegalProposals:
		msgIllegalProposals, processed := m.(*msg.IllegalProposals)
		if processed {
			n.listener.OnIllegalProposalReceived(msgItem.ID, &msgIllegalProposals.Proposals)
		}
	case msg.CmdIllegalVotes:
		msgIllegalVotes, processed := m.(*msg.IllegalVotes)
		if processed {
			n.listener.OnIllegalVotesReceived(msgItem.ID, &msgIllegalVotes.Votes)
		}
	case dmsg.CmdConfirm:
		msgConfirm, processed := m.(*dmsg.ConfirmMsg)
		if processed {
			n.listener.OnConfirmReceived(msgItem.ID, msgConfirm.Confirm, msgConfirm.Height)
		}
	case dmsg.CmdSmallCroTx:
		msgCro, processed := m.(*dmsg.SmallCroTx)
		if processed {
			n.listener.OnSmallCroTxReceived(msgItem.ID, msgCro)
		}
	case dmsg.CmdFailedWithdrawTx:
		withdrawTx, processed := m.(*dmsg.FailedWithdrawTx)
		if processed {
			n.listener.OnFailedWithdrawTxReceived(msgItem.ID, withdrawTx)
		}
	case dpos_msg.CmdDArbiter:
		msg, processed := m.(*dpos_msg.DArbiter)
		if processed {
			n.listener.OnLayer2Msg(msgItem.ID, msg)
		}
	case dpos_msg.CmdRequireArbiters:
		msg, processed := m.(*dpos_msg.RequireArbiter)
		if processed {
			n.listener.OnLayer2Msg(msgItem.ID, msg)
		}
	case dpos_msg.CmdRequireArbitersSignature:
		msg, processed := m.(*dpos_msg.RequireArbitersSignature)
		if processed {
			n.listener.OnLayer2Msg(msgItem.ID, msg)
		}
	case dpos_msg.CmdFeedbackArbiterSignature:
		msg, processed := m.(*dpos_msg.FeedBackArbitersSignature)
		if processed {
			n.listener.OnLayer2Msg(msgItem.ID, msg)
		}
	}
}

func (n *Network) changeView() {
	n.listener.OnChangeView()
}

func (n *Network) UpdatePeers(currentPeers []peer.PID, nextPeers []peer.PID) {
	Info("[UpdatePeers]", "self account:", common.BytesToHexString(n.publicKey))
	for _, p := range currentPeers {
		if bytes.Equal(n.publicKey, p[:]) {
			n.p2pServer.ConnectPeers(currentPeers, nextPeers)
			return
		}
	}

	for _, p := range nextPeers {
		if bytes.Equal(n.publicKey, p[:]) {
			n.p2pServer.ConnectPeers(currentPeers, nextPeers)
			return
		}
	}
	Info("[UpdatePeers] i am not in peers", "self account:", common.BytesToHexString(n.publicKey))
	n.p2pServer.ConnectPeers(nil, nil)
}

func (n *Network) handleMessage(pid peer.PID, msg elap2p.Message) {
	n.messageQueue <- &messageItem{pid, msg}
}

func (n *Network) badNetwork() {
	Info("badnet workd")
	n.listener.OnBadNetwork()
}

func (n *Network) recover() {
	Info("network recover")
	n.listener.OnRecover()
}

func (n *Network) AddDirectLinkAddr(pid peer.PID, addr string) {
	n.p2pServer.AddAddr(pid, addr)
}

func (n *Network) SendMessageToPeer(id peer.PID, msg elap2p.Message) error {
	Info("[SendMessageToPeer] msg:", msg.CMD(), id.String())
	return n.p2pServer.SendMessageToPeer(id, msg)
}

func (n *Network) BroadcastMessage(msg elap2p.Message) {
	Info("[BroadcastMessage] msg:", msg.CMD())
	n.p2pServer.BroadcastMessage(msg)
}

// DumpPeersInfo returns an array consisting of all peers state in connect list.
//
// This function is safe for concurrent access and is part of the
// IServer interface implementation.
func (n *Network) DumpPeersInfo() []*p2p.PeerInfo {
	return n.p2pServer.DumpPeersInfo()
}

func NewNetwork(cfg *NetworkConfig) (*Network, error) {
	network := &Network{
		listener:     cfg.Listener,
		publicKey:    cfg.PublicKey,
		announceAddr: cfg.AnnounceAddr,

		messageQueue:   make(chan *messageItem, 10000),
		quit:           make(chan bool),
		badNetworkChan: make(chan bool),
		changeViewChan: make(chan bool),
		recoverChan:    make(chan bool),
	}

	notifier := p2p.NewNotifier(p2p.NFNetStabled|p2p.NFBadNetwork, network.notifyFlag)

	var pid peer.PID
	copy(pid[:], cfg.Account.PublicKeyBytes())
	server, err := p2p.NewServer(&p2p.Config{
		DataDir:        cfg.DataPath,
		PID:            pid,
		EnableHub:      true,
		Localhost:      cfg.IPAddress,
		MagicNumber:    cfg.Magic,
		DefaultPort:    cfg.DefaultPort,
		TimeSource:     cfg.MedianTime,
		MaxNodePerHost: cfg.MaxNodePerHost,
		CreateMessage:  createMessage,
		HandleMessage:  network.handleMessage,
		PingNonce:      network.GetCurrentHeight,
		PongNonce:      network.GetCurrentHeight,
		Sign:           cfg.Account.Sign,
		StateNotifier:  notifier,
	})
	if err != nil {
		return nil, err
	}

	network.p2pServer = server
	return network, nil
}

func createMessage(hdr elap2p.Header, r net.Conn) (message elap2p.Message, err error) {
	switch hdr.GetCMD() {
	case elap2p.CmdBlock:
		message = dmsg.NewBlockMsg([]byte{})
	case msg.CmdAcceptVote:
		message = &msg.Vote{Command: msg.CmdAcceptVote}
	case msg.CmdReceivedProposal:
		message = &msg.Proposal{}
	case msg.CmdRejectVote:
		message = &msg.Vote{Command: msg.CmdRejectVote}
	case msg.CmdInv:
		message = &msg.Inventory{}
	case msg.CmdGetBlock:
		message = &msg.GetBlock{}
	case msg.CmdGetBlocks:
		message = &msg.GetBlocks{}
	case msg.CmdResponseBlocks:
		message = &msg.ResponseBlocks{}
	case msg.CmdRequestConsensus:
		message = &dmsg.RequestConsensus{}
	case msg.CmdResponseConsensus:
		message = &dmsg.ResponseConsensus{}
	case msg.CmdRequestProposal:
		message = &msg.RequestProposal{}
	case msg.CmdIllegalProposals:
		message = &msg.IllegalProposals{}
	case msg.CmdIllegalVotes:
		message = &msg.IllegalVotes{}
	case msg.CmdSidechainIllegalData:
		message = &msg.SidechainIllegalData{}
	case msg.CmdResponseInactiveArbitrators:
		message = &msg.ResponseInactiveArbitrators{}
	case dmsg.CmdConfirm:
		message = &dmsg.ConfirmMsg{}
	case dmsg.CmdSmallCroTx:
		message = &dmsg.SmallCroTx{}
	case dmsg.CmdFailedWithdrawTx:
		message = &dmsg.FailedWithdrawTx{}
	case dpos_msg.CmdDArbiter:
		message = &dpos_msg.DArbiter{}
	case dpos_msg.CmdRequireArbiters:
		message = &dpos_msg.RequireArbiter{}
	case dpos_msg.CmdRequireArbitersSignature:
		message = &dpos_msg.RequireArbitersSignature{}
	case dpos_msg.CmdFeedbackArbiterSignature:
		message = &dpos_msg.FeedBackArbitersSignature{}
	default:
		return nil, errors.New("Received unsupported message, CMD " + hdr.GetCMD())
	}

	errmsg := message.Deserialize(r)
	if errmsg != nil {
		return nil, errors.New("createMessage deserialize error " + message.CMD())
	}
	return message, nil
}
