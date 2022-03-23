package dpos_msg

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure RequireArbiter implement p2p.Message interface.
var _ p2p.Message = (*RequireArbiter)(nil)

type RequireArbiter struct {
	PID       [33]byte
	IsCurrent bool
}

func (msg *RequireArbiter) CMD() string {
	return CmdRequireArbiters
}

func (msg *RequireArbiter) MaxLength() uint32 {
	return 35
}

func (msg *RequireArbiter) Serialize(w io.Writer) error {
	_, err := w.Write(msg.PID[:])
	if err != nil {
		return err
	}
	if msg.IsCurrent == true {
		err = common.WriteUint8(w, 1)
	} else {
		err = common.WriteUint8(w, 0)
	}
	return err
}

func (msg *RequireArbiter) Deserialize(r io.Reader) error {
	pid := make([]byte, 33)
	_, err := r.Read(pid)
	if err != nil {
		return err
	}
	copy(msg.PID[:], pid)

	res, err := common.ReadUint8(r)
	if err != nil {
		return err
	}
	if res == 1 {
		msg.IsCurrent = true
	} else {
		msg.IsCurrent = false
	}
	return nil
}
