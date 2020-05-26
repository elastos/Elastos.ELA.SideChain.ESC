package dpos

import (
	"bytes"
	"errors"
	"fmt"

	dmsg "github.com/elastos/Elastos.ELA.SideChain.ETH/dpos/msg"

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
	IPAddress   string
	Magic       uint32
	DefaultPort uint16

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
	RecoverTimeout()
}

type StatusSyncEventListener interface {
	OnPing(id dpeer.PID, height uint32)
	OnPong(id dpeer.PID, height uint32)
	OnBlock(id dpeer.PID, block *dmsg.BlockMsg)
	OnInv(id dpeer.PID, blockHash common.Uint256)
	OnGetBlock(id dpeer.PID, blockHash common.Uint256)
	OnGetBlocks(id dpeer.PID, startBlockHeight, endBlockHeight uint32)
	OnResponseBlocks(id dpeer.PID, blockConfirms []*dmsg.BlockMsg)
	OnRequestConsensus(id dpeer.PID, height uint32)
	OnResponseConsensus(id dpeer.PID, status *msg.ConsensusStatus)
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
	OnRecoverTimeout()

	OnBlockReceived(b *dmsg.BlockMsg, confirmed bool)
	OnConfirmReceived(c *payload.Confirm, height uint32)
}

type messageItem struct {
	ID      peer.PID
	Message elap2p.Message
}

type Network struct {
	listener           NetworkEventListener
	proposalDispatcher *Dispatcher
	publicKey          []byte
	announceAddr       func()

	p2pServer    p2p.Server
	messageQueue chan *messageItem
	quit         chan bool

	badNetworkChan     chan bool
	changeViewChan     chan bool
	recoverChan        chan bool
	recoverTimeoutChan chan bool

	GetCurrentHeight func(pid peer.PID) uint64
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
			case <-n.recoverTimeoutChan:
				n.recoverTimeout()
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

func (n *Network) processMessage(msgItem *messageItem) {
	m := msgItem.Message
	Info("ProcessMessage:", m.CMD())
	switch m.CMD() {
	case msg.CmdReceivedProposal:
		msgProposal, processed := m.(*msg.Proposal)
		if processed {
			//fmt.Println(msgProposal)
			n.listener.OnProposalReceived(msgItem.ID, &msgProposal.Proposal)
		}
	case msg.CmdAcceptVote:
		msgVote, processed := m.(*msg.Vote)
		if processed {
			//fmt.Println(msgVote)
			n.listener.OnVoteAccepted(msgItem.ID, &msgVote.Vote)
		}
	case msg.CmdRejectVote:
		msgVote, processed := m.(*msg.Vote)
		if processed {
			//fmt.Println(msgVote)
			n.listener.OnVoteRejected(msgItem.ID, &msgVote.Vote)
		}
	case msg.CmdPing:
		msgPing, processed := m.(*msg.Ping)
		if processed {
			//fmt.Println(msgPing)
			n.listener.OnPing(msgItem.ID, uint32(msgPing.Nonce))
		}
	case msg.CmdPong:
		msgPong, processed := m.(*msg.Pong)
		if processed {
			//fmt.Println(msgPong)
			n.listener.OnPong(msgItem.ID, uint32(msgPong.Nonce))
		}
	case elap2p.CmdBlock:
		blockMsg, processed := m.(*dmsg.BlockMsg)
		if processed {
			//TODO completed this
			fmt.Println(blockMsg)
			//n.listener.OnBlock(msgItem.ID, block)
		}
	case msg.CmdInv:
		msgInv, processed := m.(*msg.Inventory)
		if processed {
			//fmt.Println(msgInv)
			n.listener.OnInv(msgItem.ID, msgInv.BlockHash)
		}
	case msg.CmdGetBlock:
		msgGetBlock, processed := m.(*msg.GetBlock)
		if processed {
			//fmt.Println(msgGetBlock)
			n.listener.OnGetBlock(msgItem.ID, msgGetBlock.BlockHash)
		}
	case msg.CmdGetBlocks:
		msgGetBlocks, processed := m.(*msg.GetBlocks)
		if processed {
			//fmt.Println(msgGetBlocks)
			n.listener.OnGetBlocks(msgItem.ID, msgGetBlocks.StartBlockHeight, msgGetBlocks.EndBlockHeight)
		}
	case msg.CmdResponseBlocks:
		//msgResponseBlocks, processed := m.(*dmsg.BlockMsg)
		//if processed {
			//n.listener.OnResponseBlocks(msgItem.ID, msgResponseBlocks)
		//}
	case msg.CmdRequestConsensus:
		msgRequestConsensus, processed := m.(*msg.RequestConsensus)
		if processed {
			//fmt.Println(msgRequestConsensus)
			n.listener.OnRequestConsensus(msgItem.ID, msgRequestConsensus.Height)
		}
	case msg.CmdResponseConsensus:
		msgResponseConsensus, processed := m.(*msg.ResponseConsensus)
		if processed {
			//fmt.Println(msgResponseConsensus)
			n.listener.OnResponseConsensus(msgItem.ID, &msgResponseConsensus.Consensus)
		}
	case msg.CmdRequestProposal:
		msgRequestProposal, processed := m.(*msg.RequestProposal)
		if processed {
			//fmt.Println(msgRequestProposal)
			n.listener.OnRequestProposal(msgItem.ID, msgRequestProposal.ProposalHash)
		}
	case msg.CmdIllegalProposals:
		msgIllegalProposals, processed := m.(*msg.IllegalProposals)
		if processed {
			//fmt.Println(msgIllegalProposals)
			n.listener.OnIllegalProposalReceived(msgItem.ID, &msgIllegalProposals.Proposals)
		}
	case msg.CmdIllegalVotes:
		msgIllegalVotes, processed := m.(*msg.IllegalVotes)
		if processed {
			//fmt.Println(msgIllegalVotes)
			n.listener.OnIllegalVotesReceived(msgItem.ID, &msgIllegalVotes.Votes)
		}
	}
}

func (n *Network) changeView() {
	Info("net changeView")
	n.listener.OnChangeView()
}

func (n *Network) UpdatePeers(peers []peer.PID) {
	for _, p := range peers {
		if bytes.Equal(n.publicKey, p[:]) {
			n.p2pServer.ConnectPeers(peers)
			return
		}
	}
	Info("[UpdatePeers] i am not in peers")
	n.p2pServer.ConnectPeers(nil)
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

func (n *Network) recoverTimeout() {
	Info("network recoverTimeout")
	n.listener.OnRecoverTimeout()
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

func NewNetwork(cfg *NetworkConfig) (*Network, error) {
	network := &Network{
		listener:           cfg.Listener,
		proposalDispatcher: cfg.ProposalDispatcher,
		publicKey:          cfg.PublicKey,
		announceAddr:       cfg.AnnounceAddr,

		messageQueue:       make(chan *messageItem, 10000),
		quit:               make(chan bool),
		badNetworkChan:     make(chan bool),
		changeViewChan:     make(chan bool),
		recoverChan:        make(chan bool),
		recoverTimeoutChan: make(chan bool),
	}

	notifier := p2p.NewNotifier(p2p.NFNetStabled|p2p.NFBadNetwork, network.notifyFlag)

	var pid peer.PID
	copy(pid[:], cfg.Account.PublicKeyBytes())
	server, err := p2p.NewServer(&p2p.Config{
		DataDir:          cfg.DataPath,
		PID:              pid,
		EnableHub:        true,
		Localhost:        cfg.IPAddress,
		MagicNumber:      cfg.Magic,
		DefaultPort:      cfg.DefaultPort,
		TimeSource:       cfg.MedianTime,
		MakeEmptyMessage: makeEmptyMessage,
		HandleMessage:    network.handleMessage,
		PingNonce:        network.GetCurrentHeight,
		PongNonce:        network.GetCurrentHeight,
		Sign:             cfg.Account.Sign,
		StateNotifier:    notifier,
	})
	if err != nil {
		return nil, err
	}

	network.p2pServer = server
	return network, nil
}

func makeEmptyMessage(cmd string) (message elap2p.Message, err error) {
	switch cmd {
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
		message = &msg.RequestConsensus{}
	case msg.CmdResponseConsensus:
		message = &msg.ResponseConsensus{}
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
	default:
		return nil, errors.New("Received unsupported message, CMD " + cmd)
	}
	return message, nil
}
