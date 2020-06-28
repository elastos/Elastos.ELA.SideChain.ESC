// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"crypto/rand"
	"testing"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/stretchr/testify/assert"
)

func init()  {
	InitLog(0, 0, 0, "")
}

func TestStartAndCheckProposal(t *testing.T) {
	ac, err := account.NewAccount()
	assert.NoError(t, err)

	data := make([]byte, 32)
	rand.Read(data)
	blockHash, err := common.Uint256FromBytes(data)
	assert.NoError(t, err)
	proposal, err := StartProposal(daccount.New(ac), *blockHash, 0)
	assert.NoError(t, err)

	err = CheckProposal(proposal)
	assert.NoError(t, err)
}