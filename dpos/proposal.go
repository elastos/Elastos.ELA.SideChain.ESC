// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/account"
)

func StartProposal(ac account.Account, blockHash common.Uint256, viewOffset uint32) (*payload.DPOSProposal, error) {
	Info("[StartProposal] start")
	defer Info("[StartProposal] end")
	proposal := &payload.DPOSProposal{Sponsor: ac.PublicKeyBytes(),
		BlockHash: blockHash, ViewOffset: viewOffset}
	sign, err := ac.SignProposal(proposal)
	if err != nil {
		Error("[StartProposal] start proposal failed:", err.Error())
		return nil, err
	}
	Info("[StartProposal] hash:", proposal.Hash().String())
	proposal.Sign = sign

	return proposal, nil
}

func CheckProposal(proposal *payload.DPOSProposal) error {
	pk, err := crypto.DecodePoint(proposal.Sponsor)
	if err != nil {
		Error("[CheckProposal] decode signer "+"error, details: ", err)
		return err
	}

	if err := crypto.Verify(*pk, proposal.Data(), proposal.Sign); err != nil {
		Error("[CheckProposal] sign verify "+"error, details: ", err)
		return err
	}
	return nil
}
