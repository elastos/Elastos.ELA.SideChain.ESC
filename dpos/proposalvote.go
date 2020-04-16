package dpos

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/account"
)

func StartVote(ProposalHash *common.Uint256, isAcceipt bool, ac account.Account) (*payload.DPOSProposalVote, error) {
	Info("[StartVote] start")
	defer Info("[StartVote] end")

	vote := &payload.DPOSProposalVote{
		ProposalHash: *ProposalHash,
		Accept:       isAcceipt,
		Signer:       ac.PublicKeyBytes(),
	}

	sign, err := ac.SignVote(vote)
	if err != nil {
		return nil, err
	}
	vote.Sign = sign

	return vote, nil
}

func CheckVote(vote *payload.DPOSProposalVote) error {
	pk, err := crypto.DecodePoint(vote.Signer)
	if err != nil {
		Error("[CheckProposal] decode signer " + "error, details: ", err)
		return err
	}

	if err := crypto.Verify(*pk, vote.Data(), vote.Sign); err != nil {
		Error("[CheckProposal] sign verify " + "error, details: ", err)
		return err
	}
	return nil
}