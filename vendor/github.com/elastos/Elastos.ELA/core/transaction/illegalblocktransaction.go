// Copyright (c) 2017-2021 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//
package transaction

import (
	"errors"
	"math"

	"github.com/elastos/Elastos.ELA/blockchain"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaerr "github.com/elastos/Elastos.ELA/errors"
)

type IllegalBlockTransaction struct {
	BaseTransaction
}

func (t *IllegalBlockTransaction) CheckTransactionInput() error {
	if len(t.Inputs()) != 0 {
		return errors.New("no cost transactions must has no input")
	}
	return nil
}

func (t *IllegalBlockTransaction) CheckTransactionOutput() error {

	if len(t.Outputs()) > math.MaxUint16 {
		return errors.New("output count should not be greater than 65535(MaxUint16)")
	}
	if len(t.Outputs()) != 0 {
		return errors.New("no cost transactions should have no output")
	}

	return nil
}

func (t *IllegalBlockTransaction) CheckAttributeProgram() error {
	if len(t.Programs()) != 0 {
		return errors.New("illegal block transactions should have one and only one program")
	}
	if len(t.Attributes()) != 0 {
		return errors.New("illegal block transactions should have no programs")
	}
	return nil
}

func (t *IllegalBlockTransaction) CheckTransactionPayload() error {
	switch t.Payload().(type) {
	case *payload.DPOSIllegalBlocks:
		return nil
	}

	return errors.New("invalid payload type")
}

func (t *IllegalBlockTransaction) IsAllowedInPOWConsensus() bool {
	return true
}

func (t *IllegalBlockTransaction) SpecialContextCheck() (elaerr.ELAError, bool) {
	p, ok := t.Payload().(*payload.DPOSIllegalBlocks)
	if !ok {
		return elaerr.Simple(elaerr.ErrTxPayload, errors.New("invalid payload")), true
	}

	if t.parameters.BlockChain.GetState().SpecialTxExists(t) {
		return elaerr.Simple(elaerr.ErrTxDuplicate, errors.New("tx already exists")), true
	}

	if err := blockchain.CheckDPOSIllegalBlocks(p); err != nil {
		return elaerr.Simple(elaerr.ErrTxPayload, err), true
	}

	return nil, true
}
