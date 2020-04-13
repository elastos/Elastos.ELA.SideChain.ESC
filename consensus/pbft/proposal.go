package pbft

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/rlp"
)

type Proposal struct {
	Sponsor    common.Address
	BlockHash  common.Hash
	ViewOffset uint32
	Sign       []byte

	hash *common.Hash
}

// EncodeRLP serializes p into the Ethereum RLP proposal format.
func (p *Proposal) RlpEncodeUnsigned(w io.Writer) error {
	return rlp.Encode(w, Proposal{
		Sponsor:    p.Sponsor,
		BlockHash:  p.BlockHash,
		ViewOffset: p.ViewOffset,
		Sign:       nil,
		hash:       nil,
	})
}

// EncodeRLP serializes p into the Ethereum RLP proposal format.
func (p *Proposal) RlpEncode(w io.Writer) error {
	return rlp.Encode(w, Proposal{
		Sponsor:    p.Sponsor,
		BlockHash:  p.BlockHash,
		ViewOffset: p.ViewOffset,
		Sign:       p.Sign,
		hash:       nil,
	})
}

// DecodeRLP decodes the Ethereum
func (p *Proposal) RlpDecode(s *rlp.Stream) error {
	if err := s.Decode(p); err != nil {
		return err
	}
	return nil
}

func (p *Proposal) Hash() common.Hash {
	if p.hash == nil {
		hash := RlpHash(Proposal{
			Sponsor:    p.Sponsor,
			BlockHash:  p.BlockHash,
			ViewOffset: p.ViewOffset,
			Sign:       nil,
			hash:       nil,
		})
		p.hash = &hash
	}
	return *p.hash
}

func RlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func StartProposal(account *AccountWallet, blockHash *common.Hash) (*Proposal, error) {
	log.Info("[StartProposal] start")
	defer log.Info("[StartProposal] end")
	proposal := &Proposal{Sponsor: account.Address(),
		BlockHash: *blockHash, ViewOffset: 0}
	sign, err := account.SignProposal(proposal)
	if err != nil {
		log.Error("[StartProposal] start proposal failed:", err.Error())
		return nil, err
	}
	log.Info("[StartProposal] sponsor:", account.Address().String())
	proposal.Sign = sign

	return proposal, nil
}

func CheckProposal(proposal *Proposal) error {
	account, err := ecrecover(proposal)
	if err != nil {
		return err
	}

	//todo check account is producer
	log.Info("recover account:", account.String())
	return nil
}

func ecrecover(proposal *Proposal) (common.Address, error) {
	// Recover the public key and the Ethereum address
	buf := new(bytes.Buffer)
	err := proposal.RlpEncodeUnsigned(buf)
	if err != nil {
		log.Error("SignProposal error:", err)
	}
	pubkey, err := crypto.SigToPub(crypto.Keccak256(buf.Bytes()),  proposal.Sign)
	if err != nil {
		return common.Address{}, err
	}
	signer := crypto.PubkeyToAddress(*pubkey)
	if signer.String() != proposal.Sponsor.String() {
		return common.Address{}, errors.New("error signer")
	}
	return signer, nil
}