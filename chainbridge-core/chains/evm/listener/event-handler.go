// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package listener

import (
	"bytes"
	"context"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
)

type EventHandlers map[common.Address]EventHandlerFunc
type EventHandlerFunc func(sourceID, destId uint64, nonce uint64, handlerContractAddress common.Address, caller ChainClient) error

type ETHEventHandler struct {
	bridgeAddress common.Address
	eventHandlers EventHandlers
	client        ChainClient
}

func NewETHEventHandler(address common.Address, client ChainClient) *ETHEventHandler {
	return &ETHEventHandler{
		bridgeAddress: address,
		client:        client,
	}
}

func (e *ETHEventHandler) HandleEvent(sourceID, destID uint64, depositNonce uint64, rID [32]byte) error {
	addr, err := e.matchResourceIDToHandlerAddress(rID)
	if err != nil {
		return err
	}
	eventHandler, err := e.matchAddressWithHandlerFunc(addr)
	if err != nil {
		return err
	}

	return eventHandler(sourceID, destID, depositNonce, addr, e.client)
}

func (e *ETHEventHandler) matchResourceIDToHandlerAddress(rID [32]byte) (common.Address, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"_resourceIDToHandlerAddress\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return common.Address{}, err
	}
	input, err := a.Pack("_resourceIDToHandlerAddress", rID)
	if err != nil {
		return common.Address{}, err
	}
	msg := ethereum.CallMsg{From: common.Address{}, To: &e.bridgeAddress, Data: input}
	out, err := e.client.CallContract(context.TODO(), toCallArg(msg), nil)
	if err != nil {
		return common.Address{}, err
	}

	addr := common.Address{}
	err = a.Unpack(&addr, "_resourceIDToHandlerAddress", out)
	if err != nil {
		return common.Address{}, err
	}
	return addr, nil
}

func (e *ETHEventHandler) matchAddressWithHandlerFunc(addr common.Address) (EventHandlerFunc, error) {
	hf, ok := e.eventHandlers[addr]
	if !ok {
		log.Info("matchAddressWithHandlerFunc", "addr", addr.String())
		for a, _ := range e.eventHandlers {
			log.Info("eventHandlers address", "address", a.String())
		}
		return nil, errors.New("no corresponding event handler for this address exists")
	}
	return hf, nil
}

func (e *ETHEventHandler) RegisterEventHandler(address string, handler EventHandlerFunc) {
	if e.eventHandlers == nil {
		e.eventHandlers = make(map[common.Address]EventHandlerFunc)
	}
	e.eventHandlers[common.HexToAddress(address)] = handler
}

func toCallArg(msg ethereum.CallMsg) map[string]interface{} {
	arg := map[string]interface{}{
		"from": msg.From,
		"to":   msg.To,
	}
	if len(msg.Data) > 0 {
		arg["data"] = hexutil.Bytes(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = (*hexutil.Big)(msg.Value)
	}
	if msg.Gas != 0 {
		arg["gas"] = hexutil.Uint64(msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = (*hexutil.Big)(msg.GasPrice)
	}
	return arg
}

func OnEventHandler(sourceID, destId uint64, nonce uint64, handlerContractAddress common.Address, client ChainClient) error {
	definition := "[{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"uint8\",\"name\":\"destId\",\"type\":\"uint8\"}],\"name\":\"getDepositRecord\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	input, err := a.Pack("getDepositRecord", nonce, destId)
	if err != nil {
		return err
	}

	msg := ethereum.CallMsg{From: common.Address{}, To: &handlerContractAddress, Data: input}
	out, err := client.CallContract(context.TODO(), toCallArg(msg), nil)
	if err != nil {
		return err
	}
	out0 := common.Hash{}
	zeroBytes := make([]byte, 32)
	err = a.Unpack(&out0, "getDepositRecord", out)
	if err != nil {
		return errors.New("no handler associated with such resourceID")
	}

	if bytes.Equal(out0.Bytes(), zeroBytes) {
		return errors.New("no this deposit record on erc20handler")
	}

	log.Info("Erc20EventHandler", "source", sourceID, "Destination", destId, "out0", out0)
	return nil
}
