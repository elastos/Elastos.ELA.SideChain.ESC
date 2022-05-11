// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type RelayedChain interface {
	ChainID() uint64
	WriteArbiters(aribters []common.Address, signatures [][]byte, totalCount int) error
	GetArbiters() []common.Address
	GetSignatures() ([][crypto.SignatureLength]byte, error)
	GetTotalCount() (uint64, error)
	GetESCState() (uint8, error)
	SetESCState(state uint8) error
	GetHashSalt() (*big.Int, error)
	SetManualArbiters(arbiter []common.Address, totalSigner int) error
	GetBridgeContract() string
	PollEvents(sysErr chan<- error, stop <-chan struct{}, eventsChan chan *SetArbiterListMsg)
}

func NewRelayer(chains []RelayedChain, escChainID uint64) *Relayer {
	relayer := &Relayer{relayedChains: chains, escChainID: escChainID}
	for _, c := range chains {
		relayer.addRelayedChain(c)
	}
	relayer.errChn = make(chan error)
	relayer.stopChn = make(chan struct{})
	return relayer
}

type Relayer struct {
	relayedChains []RelayedChain
	registry      map[uint64]RelayedChain
	escChainID    uint64
	errChn        chan error
	stopChn       chan struct{}
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
	errorCount := 0
	var err error
	for _, c := range r.relayedChains {
		if c.ChainID() != chainID && chainID != 0 {
			continue
		}
		err = c.WriteArbiters(address, signatures, totalCount)
		if err != nil {
			errorCount++
			log.Error("write arbiter error", "error", err, "chainID", c.ChainID())
		}
	}
	if len(r.relayedChains) > 0 {
		if errorCount >= len(r.relayedChains)-1 {
			return err
		}
	}

	return nil
}

func (r *Relayer) SetArbiterList(arbiters []common.Address, total int, chainID uint64) error {
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
		bridgelog.Error("GetArbiters not register chainID", "chainID", chainID)
		return []common.Address{}
	}
	return c.GetArbiters()
}

func (r *Relayer) GetSignatures(chainID uint64) ([][crypto.SignatureLength]byte, error) {
	c := r.registry[chainID]
	if c == nil {
		bridgelog.Error("GetSignatures not register chainID", "chainID", chainID)
		return nil, errors.New(fmt.Sprintf("GetSignatures not register this chainid :%d", chainID))
	}
	return c.GetSignatures()
}

func (r *Relayer) GetTotalCount(chainID uint64) (uint64, error) {
	c := r.registry[chainID]
	if c == nil {
		bridgelog.Error("GetTotalCount not register chainID", "chainID", chainID)
		return 0, errors.New(fmt.Sprintf("GetTotalCount not register this chainid :%d", chainID))
	}
	return c.GetTotalCount()
}

func (r *Relayer) GetESCState(chainID uint64) (uint8, error) {
	c := r.registry[chainID]
	if c == nil {
		bridgelog.Error("GetESCState not register chainID", "chainID", chainID)
		return 0, errors.New(fmt.Sprintf("GetESCState not register this chainid :%d", chainID))
	}
	return c.GetESCState()
}

func (r *Relayer) SetESCState(state uint8) error {
	for _, c := range r.relayedChains {
		if c.ChainID() == r.escChainID {
			continue
		}
		nowState, err := c.GetESCState()
		if err != nil {
			if nowState == state {
				continue
			}
		}

		err = c.SetESCState(state)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Relayer) GetHashSalt(chainID uint64) (*big.Int, error) {
	for _, c := range r.relayedChains {
		if c.ChainID() != chainID {
			continue
		}
		return c.GetHashSalt()
	}
	return big.NewInt(0), errors.New("GetHashSalt error chainId")
}

func (r *Relayer) SetManualArbiters(arbiters []common.Address, totalCount int) error {
	for _, c := range r.relayedChains {
		if c.ChainID() != r.escChainID {
			continue
		}
		return c.SetManualArbiters(arbiters, totalCount)
	}
	return errors.New(fmt.Sprintf("not found esc chain, chainID:%d", r.escChainID))
}

func (r *Relayer) Start() {
	bridgelog.Info("Starting update relayer")
	messagesChannel := make(chan *SetArbiterListMsg)
	for _, c := range r.relayedChains {
		bridgelog.Info("Starting chain", "chainid", c.ChainID())
		if c.ChainID() == r.escChainID {
			go c.PollEvents(r.errChn, r.stopChn, messagesChannel)
		}
	}
	for {
		select {
		case m := <-messagesChannel:
			go r.route(m)
			continue
		case err := <-r.errChn:
			bridgelog.Error("poll events error", "message", err.Error())
			close(r.stopChn)
			return
		}
	}
}

func (r *Relayer) route(m *SetArbiterListMsg) {
	bridgelog.Info("route msg >>>>>>>", "addressCount", m.AddressCount, "escchainid", r.escChainID)
	signatures, err := r.GetSignatures(r.escChainID)
	if err != nil {
		bridgelog.Error("route msg getSignature failed", "error", err)
		return
	}
	totalCount, err := r.GetTotalCount(r.escChainID)
	if err != nil {
		bridgelog.Error("route msg GetTotalCount failed", "error", err)
		return
	}
	list := r.GetArbiters(r.escChainID)
	if len(list) <= 0 {
		bridgelog.Error("route msg GetArbiters size is 0")
		return
	}
	bridgelog.Info("route totalCount", "", totalCount)
	sigs := make([][]byte, len(signatures))
	for i, sig := range signatures {
		sigs[i] = make([]byte, crypto.SignatureLength)
		copy(sigs[i], sig[:])
	}
	for _, c := range r.relayedChains {
		if c.ChainID() != r.escChainID {
			bridgelog.Info("WriteArbiters chain", "chainid", c.ChainID(), "sigs", sigs)
			err = c.WriteArbiters(list, sigs, int(totalCount))
			if err != nil {
				bridgelog.Error("write Aribters error", "msg", err)
			}
		}
	}
}
