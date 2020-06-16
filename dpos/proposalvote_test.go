// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"crypto/rand"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA/account"
	"github.com/elastos/Elastos.ELA/common"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/stretchr/testify/assert"
)

func init()  {
	InitLog(0, 0, 0, "")
}

func TestStartVote(t *testing.T) {
	mrand.Seed(time.Now().Unix())
	ac, err := account.NewAccount()
	assert.NoError(t, err)

	hash := make([]byte, 32)
	rand.Read(hash)
	proposalHash, err := common.Uint256FromBytes(hash)
	assert.NoError(t, err)

	vote, err := StartVote(proposalHash, mrand.Intn(2) == 1, daccount.New(ac))
	assert.NoError(t, err)
	err = CheckVote(vote)
	assert.NoError(t, err)
}

