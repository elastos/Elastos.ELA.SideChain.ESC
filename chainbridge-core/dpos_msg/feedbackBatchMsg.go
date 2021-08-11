package dpos_msg

import (
	"io"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure FeedbackBatchMsg implement p2p.Message interface.
var _ p2p.Message = (*FeedbackBatchMsg)(nil)

type FeedbackBatchMsg struct {
	BatchMsgHash common.Hash
	Proposer  []byte

	Signer    []byte
	Signature []byte
}

func (m *FeedbackBatchMsg) CMD() string {
	return CmdFeedbackBatch
}


func (m *FeedbackBatchMsg) MaxLength() uint32 {
	return 32 + 33 + 33 + 65 + 70
}

func (m *FeedbackBatchMsg) Serialize(w io.Writer) error {
	if err := elaCom.WriteVarBytes(w, m.BatchMsgHash.Bytes()); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Proposer); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Signer); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Signature); err != nil {
		return err
	}

	return nil
}

func (m *FeedbackBatchMsg) Deserialize(r io.Reader) error {
	hash, err := elaCom.ReadVarBytes(r, 32, "BatchMsgHash")
	if err != nil {
		return err
	}
	m.BatchMsgHash.SetBytes(hash)

	pbk, err := elaCom.ReadVarBytes(r, 33, "Proposer")
	if err != nil {
		return err
	}
	m.Proposer = pbk

	signer, err := elaCom.ReadVarBytes(r, 33, "Signer")
	if err != nil {
		return err
	}
	m.Signer = signer

	sig, err := elaCom.ReadVarBytes(r, 65, "Signature")
	if err != nil {
		return err
	}
	m.Signature = sig

	return nil
}


