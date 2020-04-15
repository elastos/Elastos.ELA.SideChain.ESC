package pbft

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/crypto"
	"github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/pbft/log"
)

func StartProposal(ac account.Account, blockHash common.Uint256) (*payload.DPOSProposal, error) {
	log.Info("[StartProposal] start")
	defer log.Info("[StartProposal] end")
	proposal := &payload.DPOSProposal{Sponsor:ac.PublicKeyBytes(),
		BlockHash: blockHash, ViewOffset: 0}
	sign, err := ac.SignProposal(proposal)
	if err != nil {
		log.Error("[StartProposal] start proposal failed:", err.Error())
		return nil, err
	}
	log.Info("[StartProposal] sponsor:", ac.PublicKeyBytes())
	proposal.Sign = sign

	return proposal, nil
}

func CheckProposal(proposal *payload.DPOSProposal) error {
	//todo check account is producer

	pk, err := crypto.DecodePoint(proposal.Sponsor)
	if err != nil {
		log.Error("[CheckProposal] decode signer " + "error, details: ", err)
		return err
	}

	if err := crypto.Verify(*pk, proposal.Data(), proposal.Sign); err != nil {
		log.Error("[CheckProposal] sign verify " + "error, details: ", err)
		return err
	}
	return nil
}
