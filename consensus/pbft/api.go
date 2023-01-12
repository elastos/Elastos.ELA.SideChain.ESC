// Copyright (c) 2017-2019 The Elastos Foundation
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
//

package pbft

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
)

// API is a user facing RPC API to allow controlling the signer and voting
// mechanisms of the delegate-proof-of-stake scheme.
type API struct {
	chain consensus.ChainReader
	pbft  *Pbft
}

func (a *API) AnnounceDAddr() uint64 {
	if a.pbft.AnnounceDAddr() {
		return 1
	}
	return 0
}

func (a *API) GetAtbiterPeersInfo() []peerInfo {
	return a.pbft.GetAtbiterPeersInfo()
}

func (a *API) GetAllPeersInfo() []peerInfo {
	peers := a.pbft.GetAllArbiterPeersInfo()
	result := make([]peerInfo, 0)
	for _, peer := range peers {
		pid := peer.PID[:]
		result = append(result, peerInfo{
			NodePublicKey: common.Bytes2Hex(pid),
			IP:            peer.Addr,
			ConnState:     peer.State.String(),
			NodeVersion:   peer.NodeVersion,
		})
	}
	return result
}

func (a *API) Dispatcher() *dpos.Dispatcher {
	return a.pbft.dispatcher
}

//func (a *API) Account() daccount.Account {
//	return a.pbft.account
//}

func (a *API) Network() *dpos.Network {
	return a.pbft.network
}
