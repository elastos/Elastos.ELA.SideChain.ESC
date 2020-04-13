package pbft

import (
	"bytes"
	"crypto/rand"
	"os"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/accounts/keystore"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"

	"github.com/stretchr/testify/assert"
	"testing"
)

func randomDposProposal() *Proposal {
	var sponsor = make([]byte, len(common.Address{}))
	rand.Read(sponsor)
	blockHash := make([]byte, len(common.Hash{}))
	rand.Read(blockHash)

	sign := make([]byte, 65)
	rand.Read(sign)
	return &Proposal{
		common.BytesToAddress(sponsor),
		common.BytesToHash(blockHash),
		0,
		sign,
		nil,
	}
}

func TestProposalEncodeRLP(t *testing.T) {
	proposal1 := randomDposProposal()
	buf := new(bytes.Buffer)
	err := proposal1.RlpEncode(buf)
	if err != nil {
		t.Error("RlpEncode err:", err.Error())
	}
	proposal2 := &Proposal{}
	reader := bytes.NewReader(buf.Bytes())
	stream := rlp.NewStream(reader, uint64(reader.Len()))
	err = proposal2.RlpDecode(stream)
	if err != nil {
		t.Error("RlpDecode err:", err.Error())
	}
	assert.Equal(t, proposal1.Sponsor.Bytes(), proposal2.Sponsor.Bytes())
	assert.Equal(t, proposal1.BlockHash, proposal2.BlockHash)
	assert.Equal(t, proposal1.ViewOffset, proposal2.ViewOffset)
	assert.Equal(t, proposal1.Hash().Bytes(), proposal2.Hash().Bytes())
}

func TestStartAndCheckProposal(t *testing.T) {
	keystore := keystore.NewKeyStore("keystore",keystore.StandardScryptN, keystore.StandardScryptP)
	defer os.RemoveAll("keystore")
	account, err := keystore.NewAccount("123")
	assert.NoError(t, err)
	wallet := keystore.Wallets()[0]
	accountWallet := NewAccount(wallet, &account)
	err = keystore.Unlock(account, "123")
	assert.NoError(t, err)

	data := make([]byte, 32)
	rand.Read(data)
	blockHash := common.BytesToHash(data)
	proposal, err := StartProposal(accountWallet, &blockHash)
	assert.NoError(t, err)

	err = CheckProposal(proposal)
	assert.NoError(t, err)
}