package pbft

import (
	"bytes"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
)

type AccountWallet struct {
	 accounts.Wallet
	 account *accounts.Account
}

func NewAccount(wallet accounts.Wallet, account *accounts.Account) *AccountWallet {
	ac := wallet.Accounts()[0]
	act := &AccountWallet {wallet, &ac}
	return act
}

func (a *AccountWallet) SignProposal(proposal *Proposal)  ([]byte, error) {
	buf := new(bytes.Buffer)
	err := proposal.RlpEncode(buf)
	if err != nil {
		log.Error("SignProposal error:", err)
	}

	return a.SignData(*a.account, accounts.MimetypeDataWithValidator, buf.Bytes())
}

func (a *AccountWallet) Address() common.Address {
	return a.account.Address
}