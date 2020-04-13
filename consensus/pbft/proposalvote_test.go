package pbft

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand"
	"os"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/accounts/keystore"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"

	"github.com/stretchr/testify/assert"
)

func randomProposalVote() *ProposalVote {
	mrand.Seed(time.Now().Unix())
	proposalHash := make([]byte, len(common.Hash{}))
	rand.Read(proposalHash)
	var signer = make([]byte, len(common.Address{}))
	rand.Read(signer)
	blockHash := make([]byte, len(common.Hash{}))
	rand.Read(blockHash)

	sign := make([]byte, 65)
	rand.Read(sign)
	return &ProposalVote{
		common.BytesToHash(proposalHash),
		mrand.Intn(2) == 1,
		common.BytesToAddress(signer),
		sign,
		nil,
	}
}

func TestProposalVote_RlpEncodeAndDecode(t *testing.T) {
	vote1 := randomProposalVote()
	buf := new(bytes.Buffer)
	err := vote1.RlpEncode(buf)
	if err != nil {
		t.Error("RlpEncode err:", err.Error())
	}
	vote2 := &ProposalVote{}
	reader := bytes.NewReader(buf.Bytes())
	stream := rlp.NewStream(reader, uint64(reader.Len()))
	err = vote2.RlpDecode(stream)
	if err != nil {
		t.Error("RlpDecode err:", err.Error())
	}
	assert.Equal(t, vote1.ProposalHash.Bytes(), vote2.ProposalHash.Bytes())
	assert.Equal(t, vote1.Accept, vote2.Accept)
	assert.Equal(t, vote1.Signer.Bytes(), vote2.Signer.Bytes())
	assert.Equal(t, vote1.Sign, vote2.Sign)
	assert.Equal(t, vote1.Hash().Bytes(), vote2.Hash().Bytes())
}

func TestStartVote(t *testing.T) {
	mrand.Seed(time.Now().Unix())
	keystore := keystore.NewKeyStore("temp",keystore.StandardScryptN, keystore.StandardScryptP)
	defer os.RemoveAll("temp")
	account, err := keystore.NewAccount("123")
	assert.NoError(t, err)
	wallet := keystore.Wallets()[0]
	accountWallet := NewAccount(wallet, &account)
	err = keystore.Unlock(account, "123")
	assert.NoError(t, err)

	hash := make([]byte, 32)
	rand.Read(hash)
	proposalHash := common.BytesToHash(hash)

	vote, err := StartVote(&proposalHash, mrand.Intn(2) == 1, accountWallet)
	assert.NoError(t, err)
	err = CheckVote(vote)
	assert.NoError(t, err)
}

