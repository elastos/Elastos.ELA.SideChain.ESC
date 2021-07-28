package dpos_msg

import (
	"io"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p"

	"golang.org/x/crypto/sha3"
)


// Ensure BlockMsg implement p2p.Message interface.
var _ p2p.Message = (*DepositProposalMsg)(nil)

type DepositProposalMsg struct {
	Item DepositItem

	Proposer  []byte
	Signature []byte
}

func (m *DepositProposalMsg) CMD() string {
	return CmdDepositproposal
}

func (m *DepositProposalMsg) MaxLength() uint32 {
	return 8000
}

func (m *DepositProposalMsg) SerializeUnsigned(w io.Writer) error {
	if err := elaCom.WriteUint8(w, m.Item.SourceChainID); err != nil {
		return err
	}
	if err := elaCom.WriteUint8(w, m.Item.DestChainID); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(w, m.Item.DepositNonce); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Item.ResourceId[:]); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Item.Data); err != nil {
		return err
	}
	return nil
}

func (m *DepositProposalMsg) Serialize(w io.Writer) error {
	if err := m.SerializeUnsigned(w); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Proposer); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Signature); err != nil {
		return err
	}

	return nil
}

func (m *DepositProposalMsg) Deserialize(r io.Reader) error {
	source, err := elaCom.ReadUint8(r)
	if err != nil {
		return err
	}
	m.Item.SourceChainID = source

	dest, err := elaCom.ReadUint8(r)
	if err != nil {
		log.Error("DepositProposalMsg Deserialize DestChainID error", "error", err)
		return err
	}
	m.Item.DestChainID = dest

	nonce, err := elaCom.ReadUint64(r)
	if err != nil {
		log.Error("DepositProposalMsg Deserialize nonce error", "error", err)
		return err
	}
	m.Item.DepositNonce = nonce

	resource, err := elaCom.ReadVarBytes(r, 32, "resourceID")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize resourceID error", "error", err)
		return err
	}
	copy(m.Item.ResourceId[:], resource[:])
	data, err := elaCom.ReadVarBytes(r, 1000, "data")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize data error", "error", err)
		return err
	}
	m.Item.Data = data
	proposer, err := elaCom.ReadVarBytes(r, 33, "proposers")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize proposer error", "error", err)
		return err
	}
	m.Proposer = proposer
	signature, err := elaCom.ReadVarBytes(r, 65, "signature")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize signature error", "error", err)
		return err
	}
	m.Signature = signature
	return nil
}

func (m *DepositProposalMsg) GetHash() (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	err := rlp.Encode(hasher, m)
	if err != nil {
		log.Error("DepositProposalMsg error", "error", err)
		return common.Hash{}
	}
	hasher.Sum(hash[:0])
	return hash
}
