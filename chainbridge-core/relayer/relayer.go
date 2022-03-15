// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"bytes"
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type RelayedChain interface {
	ChainID() uint64
	WriteArbiters(aribters []common.Address, signatures [][]byte, totalCount int) error
	GetArbiters() []common.Address
	GetBridgeContract() string
}

func NewRelayer(chains []RelayedChain) *Relayer {
	relayer := &Relayer{relayedChains: chains}
	for _, c := range chains {
		relayer.addRelayedChain(c)
	}
	return relayer
}

type Relayer struct {
	relayedChains []RelayedChain
	registry      map[uint64]RelayedChain
}

func (r *Relayer) addRelayedChain(c RelayedChain) {
	if r.registry == nil {
		r.registry = make(map[uint64]RelayedChain)
	}
	chainID := c.ChainID()
	r.registry[chainID] = c
}

func (r *Relayer) UpdateArbiters(arbiters [][]byte, totalCount int,
	signatures [][]byte, chainID uint64) error {
	address := make([]common.Address, 0)
	for _, arbiter := range arbiters {
		escssaPUb, err := crypto.DecompressPubkey(arbiter)
		if err != nil {
			return err
		}
		addr := crypto.PubkeyToAddress(*escssaPUb)
		address = append(address, addr)
	}

	for _, c := range r.relayedChains {
		if c.ChainID() != chainID && chainID != 0 {
			continue
		}
		isSame := false
		nowList := c.GetArbiters()
		if len(address) == len(nowList) {
			isSame = true
			for i, arbiter := range nowList {
				if !bytes.Equal(arbiter.Bytes(), address[i].Bytes()) {
					isSame = false
					break
				}
			}
		}
		if !isSame {
			err := c.WriteArbiters(address, signatures, totalCount)
			if err != nil {
				log.Error("write arbiter error", "error", err, "chainID", c.ChainID())
			}
		}
	}
	return nil
}

func (r *Relayer) SetArbiterList(arbiters []common.Address, total int, chainID uint64) error {
	fmt.Println("SetArbiterList", arbiters, "total", total, "chainid", chainID)
	for _, c := range r.relayedChains {
		if c.ChainID() != chainID && chainID != 0 {
			continue
		}
		err := c.WriteArbiters(arbiters, [][]byte{}, total)
		if err != nil {
			log.Error("write arbiter error", "error", err, "chainID", c.ChainID())
			return err
		}
	}
	return nil
}

func (r *Relayer) GetArbiters(chainID uint64) []common.Address {
	c := r.registry[chainID]
	if c == nil {
		bridgelog.Error("not register chainID", "chainID", chainID)
		return []common.Address{}
	}
	return c.GetArbiters()
}
