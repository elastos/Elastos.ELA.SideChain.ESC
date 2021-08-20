package dpos_msg

import (
	"io"

	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure RequireArbiter implement p2p.Message interface.
var _ p2p.Message = (*RequireArbiter)(nil)

type RequireArbiter struct {
	PID [33]byte
}

func (msg *RequireArbiter) CMD() string {
	return CmdRequireArbiters
}

func (msg *RequireArbiter) MaxLength() uint32 {
	return 34
}

func (msg *RequireArbiter) Serialize(w io.Writer) error {
	_, err := w.Write(msg.PID[:])
	return err
}

func (msg *RequireArbiter) Deserialize(r io.Reader) error {
	pid := make([]byte, 33)
	_, err := r.Read(pid)
	if err != nil {
		return err
	}
	copy(msg.PID[:], pid)
	return nil
}
