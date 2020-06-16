// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"bytes"
	"testing"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p/msg"

	"github.com/stretchr/testify/assert"
)

func TestMessage_SerializeDeserialize(t *testing.T) {
	ivHash, _ := common.Uint256FromHexString("8a6cb4b5ff1a4f8368c6513a536c663381e3fdeff738e9b437bd8fce3fb30b62")
	ivMsg := msg.NewInv()
	iv := &msg.InvVect{
		Type: msg.InvTypeAddress,
		Hash: *ivHash,
	}
	err := ivMsg.AddInvVect(iv)
	assert.NoError(t, err)
	ivMsgBuf := new(bytes.Buffer)
	err = ivMsg.Serialize(ivMsgBuf)
	assert.NoError(t, err)

	elaMsg := &ElaMsg{
		Type: Inv,
		Msg:  ivMsgBuf.Bytes(),
	}
	elaMsgBuf := new(bytes.Buffer)
	err = elaMsg.Serialize(elaMsgBuf)
	assert.NoError(t, err)

	var newElaMsg ElaMsg
	err = newElaMsg.Deserialize(elaMsgBuf)
	assert.NoError(t, err)
	assert.Equal(t, Inv, newElaMsg.Type)
	assert.Equal(t, ivMsgBuf.Bytes(), newElaMsg.Msg)
}
