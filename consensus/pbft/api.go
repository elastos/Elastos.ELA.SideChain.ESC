package pbft

import (
	"fmt"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"

	elapeer "github.com/elastos/Elastos.ELA/dpos/p2p/peer"
	"github.com/elastos/Elastos.ELA/events"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	chain consensus.ChainReader
}

func (a *API) AnnounceDAddr(pid string) uint64 {
	fmt.Println("Announce DAddr ", pid)
	producers := make([]elapeer.PID, 1)
	node0 := common.Hex2Bytes(pid)
	copy(producers[0][:], node0)
	events.Notify(events.ETDirectPeersChanged, producers)

	return 0
}
