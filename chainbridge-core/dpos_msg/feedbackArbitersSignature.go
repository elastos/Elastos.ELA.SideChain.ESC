package dpos_msg

import (
	"io"

	elaCom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure FeedBackArbitersSignature implement p2p.Message interface.
var _ p2p.Message = (*FeedBackArbitersSignature)(nil)

type FeedBackArbitersSignature struct {
	Producer   []byte
	Signature []byte
}

func (m *FeedBackArbitersSignature) CMD() string {
	return CmdFeedbackArbiterSignature
}


func (m *FeedBackArbitersSignature) MaxLength() uint32 {
	return 33 + 65 + 2
}

func (m *FeedBackArbitersSignature) Serialize(w io.Writer) error {
	if err := elaCom.WriteVarBytes(w, m.Producer); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, m.Signature); err != nil {
		return err
	}

	return nil
}

func (m *FeedBackArbitersSignature) Deserialize(r io.Reader) error {
	signer, err := elaCom.ReadVarBytes(r, 33, "Signer")
	if err != nil {
		return err
	}
	m.Producer = signer

	sig, err := elaCom.ReadVarBytes(r, 65, "Signature")
	if err != nil {
		return err
	}
	m.Signature = sig

	return nil
}


