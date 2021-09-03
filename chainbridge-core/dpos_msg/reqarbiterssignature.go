package dpos_msg

import (
	"io"

	"github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/p2p"
)

// Ensure RequireArbitersSignature implement p2p.Message interface.
var _ p2p.Message = (*RequireArbitersSignature)(nil)

type RequireArbitersSignature struct {
	PID [33]byte
	ArbiterCount uint8
}

func (msg *RequireArbitersSignature) CMD() string {
	return CmdRequireArbitersSignature
}

func (msg *RequireArbitersSignature) MaxLength() uint32 {
	return 35
}

func (msg *RequireArbitersSignature) Serialize(w io.Writer) error {
	_, err := w.Write(msg.PID[:])
	if err != nil {
		return err
	}
	err = common.WriteUint8(w, msg.ArbiterCount)
	return err
}

func (msg *RequireArbitersSignature) Deserialize(r io.Reader) error {
	pid := make([]byte, 33)
	_, err := r.Read(pid)
	if err != nil {
		return err
	}
	copy(msg.PID[:], pid)

	msg.ArbiterCount, err = common.ReadUint8(r)
	return err
}
