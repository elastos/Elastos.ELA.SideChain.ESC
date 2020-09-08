// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/dtime"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"

	"github.com/stretchr/testify/assert"
)

var (
	key, _       = common.HexStringToBytes("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	key0, _      = common.HexStringToBytes("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	key1, _      = common.HexStringToBytes("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	blockHash, _ = common.Uint256FromHexString("6e66b9b3732e8755d5230a4f4c06ff40cdc82758ef7598739e656f4ffb159558")
)

func init() {
	InitLog(0, 0, 0, "")
}

func getTestWallet(prvkey []byte, passphrase string) (daccount.Account, error) {
	ac, err := account.NewAccountWithPrivateKey(prvkey)
	if err != nil {
		return nil, err
	}
	return daccount.New(ac), nil
}

func getProducerList() [][]byte {
	ac, _ := getTestWallet(key0, "node0")
	producers := make([][]byte, 0)
	producers = append(producers, ac.PublicKeyBytes())

	ac, _ = getTestWallet(key1, "node1")
	producers = append(producers, ac.PublicKeyBytes())

	return producers
}

var proposalch chan *msg.Proposal
var votech chan *msg.Vote

func TestExampleNormalVote(t *testing.T) {
	proposalch = make(chan *msg.Proposal, 1)
	votech = make(chan *msg.Vote, 1)
	wg := &sync.WaitGroup{}
	onConfirm := func(confirm *payload.Confirm) error {
		Info("node0 confirm", confirm.Proposal.BlockHash)
		return nil
	}
	unconfirm := func(confirm *payload.Confirm) error {
		Info("node0 unconfirm", confirm.Proposal.BlockHash)
		return nil
	}
	dispatcher := NewDispatcher(getProducerList(), onConfirm, unconfirm, 5 * time.Second, []byte{}, dtime.NewMedianTime(), nil, 0)

	// Assume that there are Node0 and Node1 in the p2p network.
	// Node0 is sponsor, Node1 is normal producer.
	go node0Loop(wg, dispatcher)
	go node1Loop(wg)

	// Create wallet for Node0.
	node0Wallet, err := getTestWallet(key0, "node0")
	assert.NoError(t, err)

	// Node0 create a proposal.
	proposal, err := StartProposal(node0Wallet, *blockHash, 0)
	assert.NoError(t, err)

	// Node0 get this proposal first.
	err, _, _ = dispatcher.ProcessProposal(peer.PID{}, proposal)
	assert.NoError(t, err)

	// Node0 broadcast the proposal to p2p network.
	fmt.Println("Node0 Broadcast proposal:", proposal.Hash().String())
	proposalch <- &msg.Proposal{*proposal}

	// Build seal

	wg.Wait()
}

func node0Loop(wg *sync.WaitGroup, dispatcher *Dispatcher) {
	wg.Add(1)
	defer wg.Done()

	for {
		select {
		case voteMsg := <-votech:
			node0ProcessVotes(&voteMsg.Vote, dispatcher)
			break
		}
		wg.Done()
	}
}

func node0ProcessVotes(vote *payload.DPOSProposalVote, dispatcher *Dispatcher) bool {
	// Node0 process the vote of proposal
	suc, finished, err := dispatcher.ProcessVote(vote)
	if err != nil {
		fmt.Println("Process vote error, ", err)
		return false
	}
	if suc == false {
		fmt.Println("process vote failed ")
		return false
	}
	if finished == false {
		fmt.Println("process is not finished ")
		return false
	}
	return true
}

func node1Loop(wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	for {
		select {
		case proposalMsg := <-proposalch:
			// Node1 vote the proposal.
			Node1ProcessProposal(&proposalMsg.Proposal)
			break
		}
		wg.Done()
	}
}

func Node1ProcessProposal(proposal *payload.DPOSProposal) {
	onConfirm := func(confirm *payload.Confirm) error {
		Info("node1 confirm", confirm.Proposal.BlockHash)
		return nil
	}
	unconfirm := func(confirm *payload.Confirm) error {
		Info("node1 unconfirm", confirm.Proposal.BlockHash)
		return nil
	}
	dispatcher := NewDispatcher(getProducerList(), onConfirm, unconfirm, 5 * time.Second, []byte{}, dtime.NewMedianTime(), nil, 0)
	node1Wallet, err := getTestWallet(key1, "node1")
	if err != nil {
		fmt.Println("node1 create account error:", err)
	}

	err, _, _ = dispatcher.ProcessProposal(peer.PID{}, proposal)
	if err != nil {
		fmt.Println("node2 process proposal failed:", err)
	}

	// Node1 vote the proposal.
	proposalHash := proposal.Hash()
	vote, err := StartVote(&proposalHash, true, node1Wallet)
	if err != nil {
		fmt.Println("Vote proposal error, ", err)
	}
	fmt.Println("Node1 vote the proposal:", vote.Hash().String())
	votech <- &msg.Vote{"voteMsg", *vote}

}

func TestProcessVote(t *testing.T) {
	onConfirm := func(confirm *payload.Confirm) error {
		return nil
	}
	unconfirm := func(confirm *payload.Confirm) error {
		return nil
	}
	wg := &sync.WaitGroup{}
	wg.Add(2)
	wallet, _ := getTestWallet(key1, "node1")
	dispatcher := NewDispatcher(getProducerList(), onConfirm, unconfirm, 5 * time.Second, []byte{}, dtime.NewMedianTime(), nil, 0)
	go func() {
		for i := 0; i < 1000; i++{
			proposal, _ := StartProposal(wallet, *randomUint256(), rand.Uint32())
			dispatcher.processingProposal = proposal
			phash := proposal.Hash()
			vote, _ := StartVote(&phash, true, wallet)
			dispatcher.ProcessVote(vote)
			time.Sleep(1)
		}
		wg.Done()
	}()

	go func() {
		for i := 0; i < 1000; i++{
			proposal, _ := StartProposal(wallet, *randomUint256(), rand.Uint32())
			dispatcher.processingProposal = proposal
			phash := proposal.Hash()
			vote, _ := StartVote(&phash, true, wallet)
			dispatcher.ProcessVote(vote)
			time.Sleep(1)
		}
		wg.Done()
	}()

	wg.Wait()
}