package pbft

import (
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	daccount "github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/elastos/Elastos.ELA/events"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	chain consensus.ChainReader
	pbft  *Pbft
}

func (a *API) AnnounceDAddr() uint64 {
	producers := a.pbft.dispatcher.GetNeedConnectProducers()
	log.Info("Announce DAddr ", "Producers:", producers)
	events.Notify(events.ETDirectPeersChanged, producers)
	return 0
}

func (a *API) Dispatcher() *dpos.Dispatcher {
	return a.pbft.dispatcher
}

func (a *API) Account() daccount.Account {
	return a.pbft.account
}

func (a *API) Network() *dpos.Network {
	return a.pbft.network
}
