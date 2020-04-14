package pbft

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/accounts/keystore"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"

	"github.com/stretchr/testify/assert"
)

var (
	key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	key0, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	key1, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	blockHash = common.HexToHash("0x6e66b9b3732e8755d5230a4f4c06ff40cdc82758ef7598739e656f4ffb159558")
)

func getTestWallet(key *ecdsa.PrivateKey, passphrase string) (*AccountWallet, error) {
	newKeyStore := keystore.NewKeyStore("temp",keystore.StandardScryptN, keystore.StandardScryptP)
	defer os.RemoveAll("temp")

	account, err := newKeyStore.ImportECDSA(key, passphrase)
	if err != nil {
		return nil, err
	}
	wallet := newKeyStore.Wallets()[0]
	accountWallet := NewAccount(wallet, &account)
	err = newKeyStore.Unlock(account, passphrase)
	if err != nil {
		return nil, err
	}
	return accountWallet, nil
}

func newProposalVote(accept bool) (*ProposalVote, error) {
	accountWallet, err := getTestWallet(key, "key")
	if err != nil {
		return nil, err
	}
	hash := make([]byte, 32)
	rand.Read(hash)
	proposalHash := common.BytesToHash(hash)
	vote := &ProposalVote{
		ProposalHash: proposalHash,
		Accept: accept,
		Signer: accountWallet.Address(),
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
	proposal, err := StartProposal(node0Wallet, &blockHash)
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
	// Node0 Broadcast proposal: 0xfd75648a8c92652aad6ea419368dc4b929254a13e0801f698efe2d6e3d7bde14
	// Node1 vote the proposal: 0x24a57439411dbea9609bccb21aa46042f78cc4c09f55e88756bc7395017094ad
	// Node0 process the vote: 0xfd75648a8c92652aad6ea419368dc4b929254a13e0801f698efe2d6e3d7bde14
}