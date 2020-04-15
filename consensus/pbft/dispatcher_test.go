package pbft

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/pbft/log"

	"github.com/stretchr/testify/assert"
)

var (
	key, _ = common.HexStringToBytes("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	key0, _ = common.HexStringToBytes("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	key1, _ = common.HexStringToBytes("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	blockHash,_ = common.Uint256FromHexString("6e66b9b3732e8755d5230a4f4c06ff40cdc82758ef7598739e656f4ffb159558")
)

func init()  {
	log.Init(0, 0, 0)
}

func getTestWallet(prvkey []byte, passphrase string) (daccount.Account, error) {
	ac, err := account.NewAccountWithPrivateKey(prvkey)
	if err != nil {
		return nil, err
	}
	return daccount.New(ac), nil
}

func newProposalVote(accept bool) (*payload.DPOSProposalVote, error) {
	accountWallet, err := getTestWallet(key, "key")
	if err != nil {
		return nil, err
	}
	hash := make([]byte, 32)
	rand.Read(hash)
	proposalHash, err := common.Uint256FromBytes(hash)
	if err != nil {
		return nil, err
	}
	vote := &payload.DPOSProposalVote{
		ProposalHash: *proposalHash,
		Accept: accept,
		Signer: accountWallet.PublicKeyBytes(),
		Sign: nil,
	}
	sign, err := accountWallet.SignVote(vote)
	if err != nil {
		return nil, err
	}
	vote.Sign = sign
	return vote, nil
}

func TestDispatcher_ProcessVote(t *testing.T) {
	dispatcher := NewDispatcher()

	// Test an accept vote
	acceptVote, err := newProposalVote(true)
	assert.NoError(t, err)
	err = dispatcher.ProcessVote(acceptVote)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dispatcher.acceptVotes))
	assert.Equal(t, acceptVote, dispatcher.acceptVotes[acceptVote.Hash()])

	// Test a reject vote
	rejectVote, err := newProposalVote(false)
	assert.NoError(t, err)
	err = dispatcher.ProcessVote(rejectVote)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(dispatcher.rejectedVotes))
	assert.Equal(t, rejectVote, dispatcher.rejectedVotes[rejectVote.Hash()])

}

func ExampleNormalVote() {
	// Assume that there are Node0 and Node1 in the p2p network.
	// Node0 is sponsor, Node1 is normal producer.

	// Create wallet for Node0.
	node0Wallet, err := getTestWallet(key0, "node0")
	if err != nil {
		fmt.Println("Create Node0 wallet error, ", err)
	}

	// Node0 create a proposal.
	proposal, err := StartProposal(node0Wallet, *blockHash)
	if err != nil {
		fmt.Println("StartProposal err, ", err)
	}

	// Node0 broadcast the proposal to p2p network.
	fmt.Println("Node0 Broadcast proposal:", proposal.Hash().String())

	// Node1 receive the proposal from network and then check it.
	err = CheckProposal(proposal)
	if err != nil {
		fmt.Println("CheckProposal err, ", err)
	}

	// Create wallet for node1.
	node1Wallet, err := getTestWallet(key1, "node1")
	if err != nil {
		fmt.Println("Create Node1 wallet error, ", err)
	}

	// Node1 vote the proposal.
	proposalHash := proposal.Hash()
	vote, err := StartVote(&proposalHash, true, node1Wallet)
	if err != nil {
		fmt.Println("Vote proposal error, ", err)
	}
	fmt.Println("Node1 vote the proposal:", vote.Hash().String())

	// Node0 process the vote of proposal
	dispatcher := NewDispatcher()
	err = dispatcher.ProcessVote(vote)
	if err != nil {
		fmt.Println("Process vote error, ", err)
	}
	fmt.Println("Node0 process the vote:", dispatcher.acceptVotes[vote.Hash()].ProposalHash.String())

	// Build seal

	// Output:
	// Node0 Broadcast proposal: 1242d8421338d84fd442840a07ff6e750800c33d754dd49f2b39b4e4d1d90c67
	// Node1 vote the proposal: e767b0adbfcd2cd368a9c07c51af13b032458670ceba788bdcb676dcd9b59da3
	// Node0 process the vote: 1242d8421338d84fd442840a07ff6e750800c33d754dd49f2b39b4e4d1d90c67
}