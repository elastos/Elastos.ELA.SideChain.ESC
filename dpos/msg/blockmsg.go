// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/p2p"
	"io"
)

// Ensure BlockMsg implement p2p.Message interface.
var _ p2p.Message = (*BlockMsg)(nil)

type BlockMsg struct {
	data []byte
}

func NewBlockMsg(data []byte) *BlockMsg {
	return &BlockMsg{data: data}
}

func (msg *BlockMsg) CMD() string {
	return p2p.CmdBlock
}

func (msg *BlockMsg) MaxLength() uint32 {
	return pact.MaxBlockContextSize
}

func (msg *BlockMsg) Serialize(w io.Writer) error {
	return common.WriteVarBytes(w, msg.data)
}

func (msg *BlockMsg) Deserialize(r io.Reader) error {
	data, err := common.ReadVarBytes(r, msg.MaxLength(), "")
	msg.data = data
	return err
}

func (msg *BlockMsg) GetData() []byte {
	return msg.data
}