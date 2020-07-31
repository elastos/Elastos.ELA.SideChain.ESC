package msg

import (
	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/elanet/pact"
	"github.com/elastos/Elastos.ELA/p2p"
	"io"
)

// Ensure BlockMsg implement p2p.Message interface.
var _ p2p.Message = (*ConfirmMsg)(nil)

type ConfirmMsg struct {
	Confirm *payload.Confirm
	Height uint64
}


func NewConfirmMsg(confirm *payload.Confirm, height uint64) *ConfirmMsg {
	return &ConfirmMsg{Confirm: confirm, Height: height}
}

func (msg *ConfirmMsg) CMD() string {
	return CmdConfirm
}

func (msg *ConfirmMsg) MaxLength() uint32 {
	return pact.MaxBlockSize
}

func (msg *ConfirmMsg) Serialize(w io.Writer) error {
	err := msg.Confirm.Serialize(w)
	if err != nil {
		return err
	}
	if err := common.WriteUint64(w, msg.Height); err != nil {
		return err
	}

	return nil
}

func (msg *ConfirmMsg) Deserialize(r io.Reader) error {
	if msg.Confirm == nil {
		msg.Confirm = &payload.Confirm{}
	}
	err := msg.Confirm.Deserialize(r)
	if err != nil {
		return err
	}
	if msg.Height, err = common.ReadUint64(r); err != nil {
		return err
	}
	return nil
}