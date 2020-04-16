package dpos

import (
	"fmt"
	"sync"
	"testing"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/dpos/p2p/msg"

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
	listener := &TestListener{}
	dispatcher := NewDispatcher(getProducerList(), listener)

	// Assume that there are Node0 and Node1 in the p2p network.
	// Node0 is sponsor, Node1 is normal producer.
	go node0Loop(wg, dispatcher)
	go node1Loop(wg)

	// Create wallet for Node0.
	node0Wallet, err := getTestWallet(key0, "node0")
	assert.NoError(t, err)

	// Node0 create a proposal.
	proposal, err := StartProposal(node0Wallet, *blockHash)
	assert.NoError(t, err)

	// Node0 get this proposal first.
	err = dispatcher.ProcessProposal(proposal)
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
	fmt.Println("Node0 process the vote:", dispatcher.acceptVotes[vote.Hash()].ProposalHash.String())
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
	listener := &TestListener{}
	dispatcher := NewDispatcher(getProducerList(), listener)
	node1Wallet, err := getTestWallet(key1, "node1")
	if err != nil {
		fmt.Println("node1 create account error:", err)
	}

	err = dispatcher.ProcessProposal(proposal)
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

type TestListener struct {
}

func (pl *TestListener) ProposalConfirmed(confirm *payload.Confirm) error {
	Info("Confirming block by chain ...")
	return nil
}
