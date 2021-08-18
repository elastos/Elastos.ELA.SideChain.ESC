// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"fmt"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type RelayedChain interface {
	PollEvents(stop <-chan struct{}, sysErr chan<- error, eventsChan chan *Message)
	Write(message *Message) error
	ChainID() uint8
	WriteArbiters(aribters []common.Address, totalCount int) error
	GetArbiters() []common.Address
}

func NewRelayer(chains []RelayedChain) *Relayer {
	return &Relayer{relayedChains: chains}
}

type Relayer struct {
	relayedChains []RelayedChain
	registry      map[uint8]RelayedChain
}

// Starts the relayer. Relayer routine is starting all the chains
// and passing them with a channel that accepts unified cross chain message format
func (r *Relayer) Start(stop <-chan struct{}, sysErr chan error) {
	log.Info("Starting relayer")
	messagesChannel := make(chan *Message)
	for _, c := range r.relayedChains {
		log.Info("Starting chain", "chainid", c.ChainID())
		r.addRelayedChain(c)
		go c.PollEvents(stop, sysErr, messagesChannel)
	}
	for {
		select {
		case m := <-messagesChannel:
			go r.route(m)
			continue
		case _ = <-stop:
			return
		}
	}
}

// Route function winds destination writer by mapping DestinationID from message to registered writer.
func (r *Relayer) route(m *Message) {
	w, ok := r.registry[m.Destination]
	if !ok {
		log.Error(fmt.Sprintf("no resolver for destID %v to send message registered", m.Destination))
		return
	}
	if err := w.Write(m); err != nil {
		log.Error("rout error", "error", err, "msg", fmt.Sprint(m))
		return
	}
}

func (r *Relayer) addRelayedChain(c RelayedChain) {
	if r.registry == nil {
		r.registry = make(map[uint8]RelayedChain)
	}
	chainID := c.ChainID()
	r.registry[chainID] = c
}

func (r *Relayer) UpdateArbiters(arbiters [][]byte, totalCount int, chainID uint8) error {
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
		if c.ChainID() != chainID && chainID  != 0 {
			continue
		}
		err := c.WriteArbiters(address, totalCount)
		if err != nil {
			log.Error("write arbiter error", "error", err, "chainID", c.ChainID())
			return err
		}
	}
	return nil
}

func (r *Relayer) GetArbiters(chainID uint8) []common.Address {
	c := r.registry[chainID]
	if c == nil {
		log.Error("not register chainID", "chainID", chainID)
		return []common.Address{}
	}
	return c.GetArbiters()
}