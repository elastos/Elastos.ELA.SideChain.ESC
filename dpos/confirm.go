// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"errors"

	"github.com/elastos/Elastos.ELA/core/types/payload"
)

func CheckConfirm(confirm *payload.Confirm) error {
	err := CheckProposal(&confirm.Proposal)
	if err != nil {
		return err
	}
	if len(confirm.Votes) <= 0 {
		return errors.New("[CheckConfirm] error, not have votes")
	}
	proposalHash := confirm.Proposal.Hash()
	for _, vote := range confirm.Votes {
		if !vote.Accept {
			return errors.New("[CheckConfirm] confirm contains " +
				"reject vote")
		}

		if !proposalHash.IsEqual(vote.ProposalHash) {
			return errors.New("[CheckConfirm] confirm contains " +
				"invalid vote")
		}

		if err := CheckVote(&vote); err != nil {
			return errors.New("[CheckConfirm] confirm contain invalid " +
				"vote: " + err.Error())
		}
	}

	return nil
}