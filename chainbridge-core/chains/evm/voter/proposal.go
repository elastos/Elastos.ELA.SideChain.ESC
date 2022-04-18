// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"io"
	"math/big"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/chainbridge-core/chains/evm/evmtransaction"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"

	elaCom "github.com/elastos/Elastos.ELA/common"
)

type Proposal struct {
	Source         uint8  // Source where message was initiated
	Destination    uint8  // Destination chain of message
	DepositNonce   uint64 // Nonce for the deposit
	ResourceId     [32]byte
	Data           []byte
	BridgeAddress  common.Address
}

func (p *Proposal) Serialize(w io.Writer) error {
	if err := elaCom.WriteUint8(w, p.Source); err != nil {
		return err
	}
	if err := elaCom.WriteUint8(w, p.Destination); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(w, p.DepositNonce); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, p.ResourceId[:]); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, p.Data); err != nil {
		return err
	}
	if err := elaCom.WriteVarBytes(w, p.BridgeAddress[:]); err != nil {
		return err
	}
	return nil
}

func (p *Proposal) Deserialize(r io.Reader) error {
	source, err := elaCom.ReadUint8(r)
	if err != nil {
		return err
	}
	p.Source = source

	dest, err := elaCom.ReadUint8(r)
	if err != nil {
		return err
	}
	p.Destination = dest

	nonce, err := elaCom.ReadUint64(r)
	if err != nil {
		return err
	}
	p.DepositNonce = nonce

	resource, err := elaCom.ReadVarBytes(r, 32, "resourceID")
	if err != nil {
		return err
	}
	copy(p.ResourceId[:], resource[:])
	data, err := elaCom.ReadVarBytes(r, 1000, "data")
	if err != nil {
		return err
	}
	p.Data = data
	address, err := elaCom.ReadVarBytes(r, 20, "BridgeAddress")
	if err != nil {
		return err
	}
	copy(p.BridgeAddress[:], address[:])
	return nil
}

func (p *Proposal) Hash() common.Hash {
	buf := new(bytes.Buffer)
	p.Serialize(buf)
	return common.BytesToHash(buf.Bytes())
}

//func (p *Proposal) Status(evmCaller ChainClient) (relayer.ProposalStatus, error) {
//	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"originChainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes32\",\"name\":\"dataHash\",\"type\":\"bytes32\"}],\"name\":\"getProposal\",\"outputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"_resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"_dataHash\",\"type\":\"bytes32\"},{\"internalType\":\"address[]\",\"name\":\"_yesVotes\",\"type\":\"address[]\"},{\"internalType\":\"address[]\",\"name\":\"_noVotes\",\"type\":\"address[]\"},{\"internalType\":\"enumBridge.ProposalStatus\",\"name\":\"_status\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_proposedBlock\",\"type\":\"uint256\"}],\"internalType\":\"structBridge.Proposal\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
//	a, err := abi.JSON(strings.NewReader(definition))
//	if err != nil {
//		return relayer.ProposalStatusInactive, err // Not sure what status to use here
//	}
//	input, err := a.Pack("getProposal", p.Source, p.DepositNonce, p.GetDataHash())
//	if err != nil {
//		return relayer.ProposalStatusInactive, err
//	}
//
//	msg := ethereum.CallMsg{From: common.Address{}, To: &p.BridgeAddress, Data: input}
//	out, err := evmCaller.CallContract(context.TODO(), toCallArg(msg), nil)
//	if err != nil {
//		return relayer.ProposalStatusInactive, err
//	}
//	type bridgeProposal struct {
//		ResourceID    [32]byte
//		DataHash      [32]byte
//		YesVotes      []common.Address
//		NoVotes       []common.Address
//		Status        uint8
//		ProposedBlock *big.Int
//	}
//	out0 := new(bridgeProposal)
//	err = a.Unpack(out0, "getProposal", out)
//	return relayer.ProposalStatus(out0.Status), nil
//}

//func (p *Proposal) VotedBy(evmCaller ChainClient, by common.Address) (bool, error) {
//	definition := "[{\"inputs\":[{\"internalType\":\"uint72\",\"name\":\"\",\"type\":\"uint72\"},{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"},{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"_hasVotedOnProposal\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
//	a, err := abi.JSON(strings.NewReader(definition))
//	if err != nil {
//		return false, err // Not sure what status to use here
//	}
//	input, err := a.Pack("_hasVotedOnProposal", idAndNonce(p.Source, p.DepositNonce), p.GetDataHash(), by)
//	if err != nil {
//		return false, err
//	}
//	msg := ethereum.CallMsg{From: common.Address{}, To: &p.BridgeAddress, Data: input}
//	out, err := evmCaller.CallContract(context.TODO(), toCallArg(msg), nil)
//	if err != nil {
//		return false, err
//	}
//	out0 := false
//	err = a.Unpack(out0, "_hasVotedOnProposal", out)
//	return out0, nil
//}

func (p *Proposal) Execute(client ChainClient) error {
	log.Debug("Executing proposal", "rid", common.Bytes2Hex(p.ResourceId[:]), "depositNonce", p.DepositNonce)
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"}],\"name\":\"executeProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return err // Not sure what status to use here
	}
	input, err := a.Pack("executeProposal", p.Source, p.DepositNonce, p.Data, p.ResourceId)
	if err != nil {
		return err
	}
	gasLimit := uint64(2000000)
	gp, err := client.GasPrice()
	if err != nil {
		return err
	}
	client.LockNonce()
	n, err := client.UnsafeNonce()
	if err != nil {
		return err
	}
	tx := evmtransaction.NewTransaction(n.Uint64(), p.BridgeAddress, big.NewInt(0), gasLimit, gp, input)
	hash, err := client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}
	log.Debug("Executed", "hash", hash.String(), "nonce", n.Uint64())
	err = client.UnsafeIncreaseNonce()
	if err != nil {
		return err
	}
	client.UnlockNonce()
	return nil
}
//
//func (p *Proposal) Vote(client ChainClient) error {
//
//	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"dataHash\",\"type\":\"bytes32\"}],\"name\":\"voteProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
//	a, err := abi.JSON(strings.NewReader(definition))
//	if err != nil {
//		return err // Not sure what status to use here
//	}
//	input, err := a.Pack("voteProposal", p.Source, p.DepositNonce, p.ResourceId, p.GetDataHash())
//	if err != nil {
//		return err
//	}
//	gasLimit := uint64(1000000)
//	gp, err := client.GasPrice()
//	if err != nil {
//		return err
//	}
//	client.LockNonce()
//	n, err := client.UnsafeNonce()
//	if err != nil {
//		return err
//	}
//	tx := evmtransaction.NewTransaction(n.Uint64(), p.BridgeAddress, big.NewInt(0), gasLimit, gp, input)
//	hash, err := client.SignAndSendTransaction(context.TODO(), tx)
//	if err != nil {
//		return err
//	}
//	log.Debug("Voted", "hash", hash.String(), "nonce", n.Uint64())
//	err = client.UnsafeIncreaseNonce()
//	if err != nil {
//		return err
//	}
//	client.UnlockNonce()
//	return nil
//}

//// CreateProposalDataHash constructs and returns proposal data hash
//func (p *Proposal) GetDataHash() common.Hash {
//	return crypto.Keccak256Hash(append(p.HandlerAddress.Bytes(), p.Data...))
//}

//func idAndNonce(srcId uint8, nonce uint64) *big.Int {
//	var data []byte
//	data = append(data, big.NewInt(int64(nonce)).Bytes()...)
//	data = append(data, uint8(srcId))
//	return big.NewInt(0).SetBytes(data)
//}
