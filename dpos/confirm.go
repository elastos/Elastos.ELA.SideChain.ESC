// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package dpos

import (
	"errors"
	"fmt"

	"github.com/elastos/Elastos.ELA/core/types/payload"
)

func CheckConfirm(confirm *payload.Confirm, minSignCount int) error {
	err := CheckProposal(&confirm.Proposal)
	if err != nil {
		return err
	}
	if len(confirm.Votes) < minSignCount {
		str := fmt.Sprintf("[CheckConfirm] error, need %d votes", minSignCount)
		return errors.New(str)
	}
	proposalHash := confirm.Proposal.Hash()
	for _, vote := range confirm.Votes {
		if !vote.Accept {
			Error("confirm contains reject vote", vote.Hash().String())
			return errors.New("[CheckConfirm] confirm contains " +
				"reject vote")
		}

		if !proposalHash.IsEqual(vote.ProposalHash) {
			Error("proposal:", proposalHash.String(), "is not equal vote proposal:", vote.ProposalHash.String())
			return errors.New("[CheckConfirm] confirm contains " +
				"invalid vote")
		}

		if err := CheckVote(&vote); err != nil {
			Error("check vote error", "error", err.Error())
			return errors.New("[CheckConfirm] confirm contain invalid " +
				"vote: " + err.Error())
		}
	}

	return nil
}