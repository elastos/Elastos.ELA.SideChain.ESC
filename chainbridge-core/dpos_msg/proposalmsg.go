package dpos_msg

import (
	"bytes"
	"io"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/p2p"
)


// Ensure BlockMsg implement p2p.Message interface.
var _ p2p.Message = (*DepositProposalMsg)(nil)

type DepositProposalMsg struct {
	SourceChainID uint8  // Source where message was initiated
	DestChainID   uint8  // Destination chain of message
	DepositNonce  uint64 // Nonce for the deposit
	ResourceId    [32]byte
	Data          []byte

	Proposer  []byte
	Signature []byte

	PID       peer.PID
}

func (m *DepositProposalMsg) CMD() string {
	return CmdDepositproposal
}

func (m *DepositProposalMsg) MaxLength() uint32 {
	return 8000
}

func (m *DepositProposalMsg) SerializeUnsigned(w io.Writer) error {
	if err := elaCom.WriteUint8(w, m.SourceChainID); err != nil {
		return err
	}
	if err := elaCom.WriteUint8(w, m.DestChainID); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(w, m.DepositNonce); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.ResourceId[:]); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Data); err != nil {
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
	m.SourceChainID = source

	dest, err := elaCom.ReadUint8(r)
	if err != nil {
		log.Error("DepositProposalMsg Deserialize DestChainID error", "error", err)
		return err
	}
	m.DestChainID = dest

	nonce, err := elaCom.ReadUint64(r)
	if err != nil {
		log.Error("DepositProposalMsg Deserialize nonce error", "error", err)
		return err
	}
	m.DepositNonce = nonce

	resource, err := elaCom.ReadVarBytes(r, 32, "resourceID")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize resourceID error", "error", err)
		return err
	}
	copy(m.ResourceId[:], resource[:])
	data, err := elaCom.ReadVarBytes(r, 1000, "data")
	if err != nil {
		log.Error("DepositProposalMsg Deserialize data error", "error", err)
		return err
	}
	m.Data = data
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

func (m *DepositProposalMsg) GetHash() common.Hash {
	buf := new(bytes.Buffer)
	m.SerializeUnsigned(buf)
	return common.BytesToHash(buf.Bytes())
}
