// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/big"
	"strings"

	ethereum "github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmtransaction"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	elaCom "github.com/elastos/Elastos.ELA/common"
)

type Proposal struct {
	Source         uint8  // Source where message was initiated
	Destination    uint8  // Destination chain of message
	DepositNonce   uint64 // Nonce for the deposit
	ResourceId     [32]byte
	Data           []byte
	BridgeAddress  common.Address
	HandlerAddress common.Address
}

func (p *Proposal) Serialize(w io.Writer) error {
	if err := elaCom.WriteUint8(w, p.Source); err != nil {
		return err
	}
	if err := elaCom.WriteUint64(w, p.DepositNonce); err != nil {
		return err
	}

	if _, err := w.Write(p.ResourceId[:]); err != nil {
		return err
	}

	if _, err := w.Write(p.Data); err != nil {
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

	nonce, err := elaCom.ReadUint64(r)
	if err != nil {
		return err
	}
	p.DepositNonce = nonce
	resource, err := elaCom.ReadBytes(r, 32)
	if err != nil {
		return err
	}
	copy(p.ResourceId[:], resource[:])

	buffer := r.(*bytes.Buffer)
	data, err := elaCom.ReadBytes(r, uint64(buffer.Len()))
	if err != nil {
		return err
	}
	p.Data = data
	return nil
}

func (p *Proposal) Hash() (hash common.Hash) {
	w := bytes.NewBuffer([]byte{})
	err := p.Serialize(w)
	if err != nil {
		log.Error("Proposal Serialize error", "error", err)
		return hash
	}
	hash = crypto.Keccak256Hash(w.Bytes())
	return hash
}

// CreateProposalDataHash constructs and returns proposal data hash
func (p *Proposal) GetDataHash() common.Hash {
	return crypto.Keccak256Hash(append(p.HandlerAddress.Bytes(), p.Data...))
}

func (p *Proposal) Status(evmCaller ChainClient) (relayer.ProposalStatus, error) {
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"originChainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes32\",\"name\":\"dataHash\",\"type\":\"bytes32\"}],\"name\":\"getProposal\",\"outputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"_resourceID\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"_dataHash\",\"type\":\"bytes32\"},{\"internalType\":\"address[]\",\"name\":\"_yesVotes\",\"type\":\"address[]\"},{\"internalType\":\"address[]\",\"name\":\"_noVotes\",\"type\":\"address[]\"},{\"internalType\":\"enumBridge.ProposalStatus\",\"name\":\"_status\",\"type\":\"uint8\"},{\"internalType\":\"uint256\",\"name\":\"_proposedBlock\",\"type\":\"uint256\"}],\"internalType\":\"structBridge.Proposal\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return relayer.ProposalStatusInactive, err // Not sure what status to use here
	}
	chainID, err := evmCaller.ChainID(context.TODO())
	if err != nil {
		log.Error("evm caller chainID is error", "error", err)
		return relayer.ProposalStatusInactive, err
	}
	log.Info("[Status getProposal]", "toChain", chainID, "source", p.Source, "depositNonce", p.DepositNonce)
	input, err := a.Pack("getProposal", p.Source, p.DepositNonce, p.GetDataHash())
	//nonceAndID := (uint64(p.DepositNonce) << 8) | uint64(p.Source)
	//log.Debug("[Status getProposal]", "source", p.Source, "DepositNonce", p.DepositNonce, "DataHash", p.GetDataHash().String(), "nonceAndID", nonceAndID, "nonceID", new(big.Int).SetUint64(nonceAndID).Bytes(), "nonceID2", common.Bytes2Hex(new(big.Int).SetUint64(nonceAndID).Bytes()))

	if err != nil {
		return relayer.ProposalStatusInactive, err
	}
	msg := ethereum.CallMsg{From: common.Address{}, To: &p.BridgeAddress, Data: input}
	out, err := evmCaller.CallContract(context.TODO(), toCallArg(msg), nil)
	if err != nil {
		return relayer.ProposalStatusInactive, err
	}
	type bridgeProposal struct {
		ResourceID    [32]byte
		DataHash      [32]byte
		YesVotes      []common.Address
		NoVotes       []common.Address
		Status        uint8
		ProposedBlock *big.Int
	}
	out0 := new(bridgeProposal)
	err = a.Unpack(out0, "getProposal", out)
	return relayer.ProposalStatus(out0.Status), nil
}

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

// proposalIsComplete returns true if the proposal state is either Passed, Transferred or Cancelled
func (p *Proposal) ProposalIsComplete(client ChainClient) bool {
	propStates, err :=  p.Status(client)
	if err != nil {
		log.Error("Failed to check proposal existence", "err", err)
		return false
	}
	chainID, _ := client.ChainID(context.TODO())
	log.Info("[ProposalIsComplete]", "status", propStates, "chainID", chainID.Uint64())
	return propStates == relayer.ProposalStatusExecuted || propStates == relayer.ProposalStatusCanceled
}

func (p *Proposal) Execute(client ChainClient) error {
	nowBlock, _ := client.LatestBlock()
	log.Info("Executing proposal", "source", p.Source, "rid", common.Bytes2Hex(p.ResourceId[:]), "depositNonce", p.DepositNonce, "data", common.Bytes2Hex(p.Data), "nowBlock", nowBlock.Uint64())
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64\",\"name\":\"depositNonce\",\"type\":\"uint64\"},{\"internalType\":\"bytes\",\"name\":\"data\",\"type\":\"bytes\"},{\"internalType\":\"bytes32\",\"name\":\"resourceID\",\"type\":\"bytes32\"}],\"name\":\"executeProposal\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return err // Not sure what status to use here
	}
	input, err := a.Pack("executeProposal", p.Source, p.DepositNonce, p.Data, p.ResourceId)
	if err != nil {
		return err
	}
	gasLimit := uint64(0)
	gp, err := client.GasPrice()
	if err != nil {
		return err
	}
	client.LockNonce()
	defer client.UnlockNonce()
	n, err := client.UnsafeNonce()
	if err != nil {
		return err
	}

	msg := ethereum.CallMsg{From: client.GetClientAddress(), To: &p.BridgeAddress, Data: input}
	gasLimit, err = client.EstimateGasLimit(context.TODO(), msg)
	if err != nil {
		return err
	}
	if gasLimit == 0 {
		return errors.New("EstimateGasLimit is 0")
	}
	nonce := n.Uint64()
	tx := evmtransaction.NewTransaction(nonce, p.BridgeAddress, big.NewInt(0), gasLimit, gp, input)
	hash, err := client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}

	err = client.UnsafeIncreaseNonce()
	if err != nil {
		log.Error("UnsafeIncreaseNonce error", "error", err)
		return err
	}

	chainID, _ := client.ChainID(context.TODO())
	nowNonce, _ := client.UnsafeNonce()
	log.Info("Executed proposal","hash", hash.String(), "chainID", chainID.Uint64(), "nonce", nonce, "gasLimit", gasLimit, "blockNumber", nowBlock.Uint64(), "dest", p.Destination, "increcedNonce", nowNonce.Uint64())
	return nil
}

func ExecuteBatch(client ChainClient, list []*Proposal) error {
	nowBlock, _ := client.LatestBlock()
	log.Info("Executing ExecuteBatch", "list", len(list))
	definition := "[{\"inputs\":[{\"internalType\":\"uint8\",\"name\":\"chainID\",\"type\":\"uint8\"},{\"internalType\":\"uint64[]\",\"name\":\"depositNonce\",\"type\":\"uint64[]\"},{\"internalType\":\"bytes[]\",\"name\":\"data\",\"type\":\"bytes[]\"},{\"internalType\":\"bytes32[]\",\"name\":\"resourceID\",\"type\":\"bytes32[]\"}],\"name\":\"executeProposalBatch\",\"outputs\":[],\"stateMutability\":\"nonpayable\", \"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return err // Not sure what status to use here
	}
	source := list[0].Source
	BridgeAddress := list[0].BridgeAddress
	nonceList := make([]uint64, 0)
	dataList := make([][]byte, 0)
	resourceID := make([][32]byte, 0)
	for _, p := range list {
		nonceList = append(nonceList, p.DepositNonce)
		dataList = append(dataList, p.Data)
		resourceID = append(resourceID, p.ResourceId)
	}
	input, err := a.Pack("executeProposalBatch", source, nonceList, dataList, resourceID)
	if err != nil {
		return err
	}
	gasLimit := uint64(0)
	gp, err := client.GasPrice()
	if err != nil {
		return err
	}
	client.LockNonce()
	defer client.UnlockNonce()
	n, err := client.UnsafeNonce()
	if err != nil {
		return err
	}

	msg := ethereum.CallMsg{From: client.GetClientAddress(), To: &BridgeAddress, Data: input}
	gasLimit, err = client.EstimateGasLimit(context.TODO(), msg)
	if err != nil {
		return err
	}
	if gasLimit == 0 {
		return errors.New("EstimateGasLimit is 0")
	}
	nonce := n.Uint64()
	tx := evmtransaction.NewTransaction(nonce, BridgeAddress, big.NewInt(0), gasLimit, gp, input)
	hash, err := client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}

	err = client.UnsafeIncreaseNonce()
	if err != nil {
		log.Error("UnsafeIncreaseNonce error", "error", err)
		return err
	}

	chainID, _ := client.ChainID(context.TODO())
	nowNonce, _ := client.UnsafeNonce()
	log.Info("Executed proposal batch ","hash", hash.String(), "chainID", chainID.Uint64(), "nonce", nonce, "gasLimit", gasLimit, "blockNumber", nowBlock.Uint64(), "increcedNonce", nowNonce.Uint64())

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
