package pbft

import (
	"crypto/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/pbft/log"

	"github.com/stretchr/testify/assert"
)

func init()  {
	log.Init(0, 0, 0)
}

func TestStartAndCheckProposal(t *testing.T) {
	ac, err := account.NewAccount()
	assert.NoError(t, err)

	data := make([]byte, 32)
	rand.Read(data)
	blockHash, err := common.Uint256FromBytes(data)
	assert.NoError(t, err)
	proposal, err := StartProposal(daccount.New(ac), *blockHash)
	assert.NoError(t, err)

	err = CheckProposal(proposal)
	assert.NoError(t, err)
}