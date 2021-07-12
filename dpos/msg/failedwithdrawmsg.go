// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package msg

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure FailedWithdrawTx implement p2p.Message interface.
var _ p2p.Message = (*FailedWithdrawTx)(nil)

type FailedWithdrawTx struct {
	signature string
	hash string
}

func NewFailedWithdrawTx(sig string, hash string) *FailedWithdrawTx {
	return &FailedWithdrawTx{signature: sig, hash: hash}
}

func (msg *FailedWithdrawTx) CMD() string {
	return CmdFailedWithdrawTx
}

func (msg *FailedWithdrawTx) MaxLength() uint32 {
	return pact.MaxBlockContextSize
}

func (msg *FailedWithdrawTx) Serialize(w io.Writer) error {
	err := common.WriteVarString(w, msg.signature)
	if err != nil {
		return err
	}
	err = common.WriteVarString(w, msg.hash)
	if err != nil {
		return err
	}
	return nil
}

func (msg *FailedWithdrawTx) Deserialize(r io.Reader) error {
	data, err := common.ReadVarString(r)
	if err != nil {
		return err
	}
	msg.signature = data

	data, err = common.ReadVarString(r)
	if err != nil {
		return err
	}
	msg.hash = data
	return err
}

func  (msg *FailedWithdrawTx) GetSignature() string {
	return msg.signature
}

func  (msg *FailedWithdrawTx) GetHash() string {
	return msg.hash
}