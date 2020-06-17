// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
	elamsg "github.com/elastos/Elastos.ELA/dpos/p2p/msg"
)

type RequestConsensus struct {
	Height uint64
}

func (msg *RequestConsensus) CMD() string {
	return elamsg.CmdRequestConsensus
}

func (msg *RequestConsensus) MaxLength() uint32 {
	return 8
}

func (msg *RequestConsensus) Serialize(w io.Writer) error {
	if err := common.WriteUint64(w, msg.Height); err != nil {
		return err
	}

	return nil
}

func (msg *RequestConsensus) Deserialize(r io.Reader) error {
	var err error
	if msg.Height, err = common.ReadUint64(r); err != nil {
		return err
	}

	return nil
}
