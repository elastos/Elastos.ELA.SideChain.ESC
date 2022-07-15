// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types"
	"github.com/elastos/Elastos.ELA/crypto"
	dp "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
	"github.com/elastos/Elastos.ELA/p2p"
	"github.com/elastos/Elastos.ELA/p2p/msg"

	"github.com/stretchr/testify/assert"
)

// MessageFunc is a message handler in peer's configuration
type MessageFunc func(peer *mockPeer, msg p2p.Message)

type mockPeer struct {
	conn net.Conn
	// These fields are set at creation time and never modified, so they are
	// safe to read from concurrently without a mutex.
	addr         string
	magic        uint32
	messageFuncs []MessageFunc
	port         uint16
	inbound      bool
}

func (p *mockPeer) SendELAMessage(msg *ElaMsg) {
	var (
		sendMsg p2p.Message
		err     error
	)

	switch msg.Type {
	case GetData:
		sendMsg, err = p.makeEmptyMessage(*p2p.BuildHeader(2, p2p.CmdGetData, []byte{}), nil)
	default:
		panic("error msg type")
	}
	if err != nil {
		Info("SendELAMessage error", err)
	}
	p.QueueMessage(sendMsg, nil)
}

func (p *mockPeer) Disconnect() {
	Info("Disconnect", p)
}

func (p *mockPeer) QueueMessage(msg p2p.Message, doneChan chan<- struct{}) {
	if err := p.writeMessage(msg); err != nil {
		p.Disconnect()
	}
	if doneChan != nil {
		doneChan <- struct{}{}
	}
}

func (p *mockPeer) SetNetConn(conn net.Conn, isInbound bool) {
	p.conn = conn
	p.inbound = isInbound
	if isInbound {
		p.addr = conn.RemoteAddr().String()
	}
}
func newMockPeer() *mockPeer {
	return &mockPeer{
		magic: 1111,
		port:  20445,
	}
}

// handleMessage will be invoked when a message received.
func (p *mockPeer) handleMessage(peer *mockPeer, msg p2p.Message) {
	for _, messageFunc := range p.messageFuncs {
		messageFunc(peer, msg)
	}
}

func (p *mockPeer) makeEmptyMessage(hdr p2p.Header, r net.Conn) (p2p.Message, error) {
	var message p2p.Message
	switch hdr.GetCMD() {
	case p2p.CmdVersion:
		message = &msg.Version{}
	case p2p.CmdGetData:
		message = &msg.GetData{}
	default:
		fmt.Println("unkown message:", hdr.GetCMD())
	}
	return message, nil
}

// AddMessageFunc add a new message handler for the peer.
func (p *mockPeer) AddMessageFunc(messageFunc MessageFunc) {
	if messageFunc != nil {
		p.messageFuncs = append(p.messageFuncs, messageFunc)
	}
}

func (p *mockPeer) readMessage() (p2p.Message, error) {
	msg, err := p2p.ReadMessage(p.conn, p.magic, p2p.ReadMessageTimeOut, p.makeEmptyMessage)
	return msg, err
}

func (p *mockPeer) writeMessage(m p2p.Message) error {
	return p2p.WriteMessage(p.conn, p.magic, m, p2p.WriteMessageTimeOut, func(message p2p.Message) (*types.DposBlock, bool) {
		return nil, false
	})
}

func (p *mockPeer) readRemoteVersionMsg() error {
	// Read their version message.
	message, err := p.readMessage()
	if err != nil {
		return err
	}
	remoteVerMsg, ok := message.(*msg.Version)
	if !ok {
		errStr := "A version message must precede all others"
		Error(errStr)
		return errors.New(errStr)
	}
	p.handleMessage(p, remoteVerMsg)
	return nil
}

func (p *mockPeer) negotiateInboundProtocol() error {
	if err := p.readRemoteVersionMsg(); err != nil {
		return err
	}
	return p.writeVersionMsg()
}

func (p *mockPeer) writeVersionMsg() error {
	msg := msg.NewVersion(1, p.port, 0, 1, 1, false, "")
	return p.writeMessage(msg)
}

func (p *mockPeer) negotiateOutboundProtocol() error {
	if err := p.writeVersionMsg(); err != nil {
		return err
	}
	return p.readRemoteVersionMsg()
}

func (p *mockPeer) start() error {
	negotiateErr := make(chan error, 1)
	go func() {
		if p.inbound {
			negotiateErr <- p.negotiateInboundProtocol()
		} else {
			negotiateErr <- p.negotiateOutboundProtocol()
		}
	}()
	select {
	case err := <-negotiateErr:
		if err != nil {
			return err
		}
	case <-time.After(5 * time.Second):
		return errors.New("protocol negotiation timeout")
	}

	go func() {
		for {
			m, err := p.readMessage()
			if err != nil {
				p.Disconnect()
				return
			}
			switch m.(type) {
			case *msg.GetData:
				fmt.Println(m)
			}
		}
	}()
	return nil
}

func mockRemotePeer(port uint16, pc chan<- *mockPeer, mc chan<- p2p.Message) error {
	listen, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := listen.Accept()
			if err != nil {
				fmt.Printf("%s can not accept, %s", listen.Addr(), err)
				return
			}
			p := newMockPeer()
			p.SetNetConn(conn, true)
			p.AddMessageFunc(func(peer *mockPeer, m p2p.Message) {
				switch m := m.(type) {
				case *msg.Version:
					pc <- peer
				default:
					mc <- m
				}
			})
			go func() {
				if err := p.start(); err != nil {
					p.Disconnect()
				}
			}()
		}
	}()
	return nil
}

func mockInboundPeer(addr string, pc chan<- *mockPeer, mc chan<- p2p.Message) error {
	// Configure peer to act as a simnet node that offers no services.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	p := newMockPeer()
	p.addr = addr
	p.SetNetConn(conn, false)
	p.AddMessageFunc(func(peer *mockPeer, m p2p.Message) {
		switch m := m.(type) {
		case *msg.Version:
			pc <- peer
		default:
			mc <- m
		}
	})

	go func() {
		if err := p.start(); err != nil {
			p.Disconnect()
		}
	}()

	return nil
}
func TestRouteMsg(t *testing.T) {
	quit := make(chan bool, 0)
	active := make(chan struct{})
	pc := make(chan *mockPeer, 1)
	mc := make(chan p2p.Message)
	err := mockRemotePeer(20338, pc, mc)
	assert.NoError(t, err)

	err = mockInboundPeer("localhost:20338", pc, mc)
	assert.NoError(t, err)

	p1 := <-pc
	p2 := <-pc

	priKey1, pubKey1, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pk1, err := pubKey1.EncodePoint(true)
	assert.NoError(t, err)

	_, pubKey2, err := crypto.GenerateKeyPair()
	assert.NoError(t, err)
	pk2, err := pubKey2.EncodePoint(true)
	assert.NoError(t, err)

	relay := make(chan struct{})
	routes := New(&Config{
		PID:  pk1,
		Addr: "localhost",
		Sign: func(data []byte) (signature []byte) {
			signature, err = crypto.Sign(priKey1, data)
			return
		},
		IsCurrent: func() bool { return true },
		RelayAddr: func(iv *msg.InvVect, data interface{}) {
			relay <- struct{}{}
		},
		OnCipherAddr: func(pid dp.PID, addr []byte) {},
	})
	routes.Start()

	// Trigger peers change continuously.
	go func() {
		var pid1, pid2 dp.PID
		copy(pid1[:], pk1)
		copy(pid2[:], pk2)
		peers := []dp.PID{pid1, pid2}
		events.Notify(events.ETDirectPeersChangedV2,
			&dp.PeersInfo{CurrentPeers: peers, NextPeers: nil})
	}()

	go func() {
		events.Notify(ETNewPeer, p1)
		active <- struct{}{}
		events.Notify(ETNewPeer, p2)
		active <- struct{}{}

		for i := 0; true; i++ {
			p := newMockPeer()
			events.Notify(ETNewPeer, p)
			active <- struct{}{}
			if i > 5 {
				events.Notify(ETDonePeer, p)
				active <- struct{}{}
			}
		}
	}()

	// Trigger address announce continuously.
	go func() {
		for {
			routes.AnnounceAddr()
		}
	}()

	// Queue getData message continuously.
	go func() {
		for {
			inv := msg.NewGetData()
			hash := common.Uint256{}
			rand.Read(hash[:])
			inv.AddInvVect(msg.NewInvVect(msg.InvTypeAddress, &hash))
			routes.OnGetData(p1, inv)
			active <- struct{}{}
		}
	}()

	// Queue inv message continuously.
	go func() {
		for {
			inv := msg.NewInv()
			hash := common.Uint256{}
			rand.Read(hash[:])
			inv.AddInvVect(msg.NewInvVect(msg.InvTypeAddress, &hash))
			routes.QueueInv(p2, inv)
			active <- struct{}{}
		}
	}()

	time.AfterFunc(2*time.Minute, func() {
		close(quit)
	})
	relayCount := 0
out:
	for {
		select {
		case <-relay:
			relayCount++
			fmt.Println(relayCount)
			if relayCount > 4 {
				t.Logf("routes relay(%d) too frequent", relayCount)
			}
		case <-active:
			time.Sleep(time.Millisecond * 5)
		case <-quit:
			break out
		}
	}
}

func TestRoutes_AppendAddr(t *testing.T) {
	routes := New(&Config{
		Addr: "localhost",
		Sign: func(data []byte) (signature []byte) {
			return
		},
		IsCurrent:    func() bool { return true },
		RelayAddr:    func(iv *msg.InvVect, data interface{}) {},
		OnCipherAddr: func(pid dp.PID, addr []byte) {},
	})

	for i := 0; i < maxKnownAddrs*10; i++ {
		addr := msg.DAddr{}
		rand.Read(addr.PID[:])
		routes.addrIndex[addr.PID] = make(map[dp.PID]common.Uint256)
		addr.Timestamp = time.Now()
		rand.Read(addr.Encode[:])
		addr.Cipher = make([]byte, 120)
		rand.Read(addr.Cipher)
		addr.Signature = make([]byte, 65)
		rand.Read(addr.Signature)
		routes.appendAddr(&addr)

		if len(routes.knownAddr) > maxKnownAddrs {
			t.Fatalf("len(routes.knownAddr) > maxKnownAddrs")
		}

		if routes.knownList.Len() > maxKnownAddrs {
			t.Fatalf("routes.knownList.Len() > maxKnownAddrs")
		}
	}
}

func TestEventNotify(t *testing.T) {
	const ET_TEST_EVENT = 10000
	events.Subscribe(func(e *events.Event) {
		switch e.Type {
		case ET_TEST_EVENT:
			fmt.Println("receive test event")
			go events.Notify(ET_TEST_EVENT, nil)
		}
	})

	go events.Notify(ET_TEST_EVENT, nil)
	time.Sleep(1 * time.Second)
}
