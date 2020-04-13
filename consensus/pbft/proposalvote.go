package pbft

import (
	"bytes"
	"errors"
	"io"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
)

type ProposalVote struct {
	ProposalHash common.Hash
	Accept bool
	Signer common.Address
	Sign  []byte

	hash *common.Hash
}

func (v *ProposalVote) RlpEncodeUnsigned(w io.Writer) error {
	return rlp.Encode(w, ProposalVote{
		ProposalHash: v.ProposalHash,
		Accept:       v.Accept,
		Signer:       v.Signer,
		Sign:         nil,
		hash:         nil,
	})
}

// EncodeRLP serializes v into the Ethereum RLP proposal format.
func (v *ProposalVote) RlpEncode(w io.Writer) error {
	return rlp.Encode(w, ProposalVote{
		ProposalHash: v.ProposalHash,
		Accept:       v.Accept,
		Signer:       v.Signer,
		Sign:         v.Sign,
		hash:         nil,
	})
}

// DecodeRLP decodes the Ethereum
func (v *ProposalVote) RlpDecode(s *rlp.Stream) error {
	if err := s.Decode(v); err != nil {
		return err
	}
	return nil
}

func (v *ProposalVote) Hash() common.Hash {
	if v.hash == nil {
		hash := RlpHash(ProposalVote{
			ProposalHash: v.ProposalHash,
			Accept:       v.Accept,
			Signer:       v.Signer,
			Sign:         nil,
			hash:         nil,
		})
		v.hash = &hash
	}
	return *v.hash
}

func StartVote(ProposalHash *common.Hash, isAcceipt bool, account *AccountWallet) (*ProposalVote, error) {
	log.Info("[StartProposal] start")
	defer log.Info("[StartProposal] end")

	vote := &ProposalVote{
		ProposalHash: *ProposalHash,
		Accept:       isAcceipt,
		Signer:       account.Address(),
	}

	sign, err := account.SignVote(vote)
	if err != nil {
		return nil, err
	}
	vote.Sign = sign

	return vote, nil
}

func CheckVote(vote *ProposalVote) error {
	signer, err := recoverSigner(vote)
	if err != nil {
		return err
	}

	log.Info("recover vote signer:", signer.String())
	return nil
}

func recoverSigner(vote *ProposalVote) (common.Address, error) {
	// Recover the public key and the Ethereum address
	buf := new(bytes.Buffer)
	err := vote.RlpEncodeUnsigned(buf)
	if err != nil {
		log.Error("SignProposal error:", err)
	}
	pubkey, err := crypto.SigToPub(crypto.Keccak256(buf.Bytes()),  vote.Sign)
	if err != nil {
		return common.Address{}, err
	}
	signer := crypto.PubkeyToAddress(*pubkey)
	if signer.String() != vote.Signer.String() {
		return common.Address{}, errors.New("error signer")
	}
	return signer, nil
}