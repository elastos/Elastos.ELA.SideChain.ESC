// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmtransaction"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

	"github.com/elastos/Elastos.ELA/events"
)

type ChainClient interface {
	LatestBlock() (*big.Int, error)
	SignAndSendTransaction(ctx context.Context, tx evmclient.CommonTransaction) (common.Hash, error)
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
	GetNonce() (*big.Int, error)
	LockNonce()
	UnlockNonce()
	GasPrice() (*big.Int, error)
	EstimateGasLimit(ctx context.Context, msg ethereum.CallMsg) (uint64, error)
	ChainID(ctx context.Context) (*big.Int, error)
	Engine() engine.ESCEngine
	GetClientAddress() common.Address
	IsContractAddress(address string) bool
}

type Proposer interface {
	Status(client ChainClient) (relayer.ProposalStatus, error)
	Execute(client ChainClient, signatures [][]byte) error
}

type MessageHandler interface {
	HandleMessage(m *relayer.Message) (Proposer, error)
}

type EVMVoter struct {
	stop    <-chan struct{}
	mh      MessageHandler
	client  ChainClient
	account *secp256k1.Keypair
}

func NewVoter(mh MessageHandler, client ChainClient, arbiterAccount *secp256k1.Keypair) *EVMVoter {
	return &EVMVoter{
		mh:      mh,
		client:  client,
		account: arbiterAccount,
	}
}
func (w *EVMVoter) HandleProposal(m *relayer.Message) (*Proposal, error) {
	prop, err := w.mh.HandleMessage(m)
	if err != nil {
		return nil, err
	}
	return prop.(*Proposal), nil
}

func (w *EVMVoter) SignAndBroadProposal(proposal *Proposal) common.Hash {
	msg := &dpos_msg.DepositProposalMsg{}
	msg.Item.SourceChainID = proposal.Source
	msg.Item.DestChainID = proposal.Destination
	msg.Item.DepositNonce = proposal.DepositNonce
	copy(msg.Item.ResourceId[:], proposal.ResourceId[:])
	msg.Item.Data = proposal.Data

	msg.Proposer, _ = hexutil.Decode(w.account.PublicKey())
	msg.Signature = w.SignData(accounts.TextHash(proposal.Hash().Bytes()))
	w.client.Engine().SendMsgProposal(msg)
	go events.Notify(dpos_msg.ETOnProposal, msg) //self is a signature
	return msg.GetHash()
}

func (w *EVMVoter) SignAndBroadProposalBatch(list []*Proposal) *dpos_msg.BatchMsg {
	msg := &dpos_msg.BatchMsg{}
	for _, pro := range list {
		it := dpos_msg.DepositItem{}
		it.SourceChainID = pro.Source
		it.DestChainID = pro.Destination
		it.DepositNonce = pro.DepositNonce
		copy(it.ResourceId[:], pro.ResourceId[:])
		it.Data = pro.Data
		msg.Items = append(msg.Items, it)
	}
	msg.Proposer, _ = hexutil.Decode(w.account.PublicKey())
	msg.Signature = w.SignData(accounts.TextHash(msg.GetHash().Bytes()))
	w.client.Engine().SendMsgProposal(msg)
	return msg
}

func (w *EVMVoter) FeedbackBatchMsg(msg *dpos_msg.BatchMsg) common.Hash {
	signer, err := w.GetPublicKey()
	if err != nil {
		return common.Hash{}
	}

	batchHash := msg.GetHash()
	feedback := &dpos_msg.FeedbackBatchMsg{
		BatchMsgHash: batchHash,
		Proposer:     msg.Proposer,
		Signer:       signer,
		Signature:    w.SignData(accounts.TextHash(batchHash.Bytes())),
	}
	if bytes.Equal(msg.Proposer, signer) {
		events.Notify(dpos_msg.ETOnProposal, feedback) //self is a signature
		return batchHash
	}
	w.client.Engine().SendMsgToPeer(feedback, msg.PID)
	return batchHash
}

func (w *EVMVoter) GetPublicKey() ([]byte, error) {
	if w.account == nil {
		return nil, errors.New("account is nil")
	}
	pbk, err := hexutil.Decode(w.account.PublicKey())
	return pbk, err
}

func (w *EVMVoter) GetSignerAddress() (common.Address, error) {
	if w.account == nil {
		return common.Address{}, errors.New("account is nil")
	}
	return w.account.CommonAddress(), nil
}

func (w *EVMVoter) SetArbiterList(arbiters []common.Address, totalCount int, signature [][]byte, bridgeAddress string) error {
	definition := "[{\"inputs\":[{\"internalType\":\"address[]\",\"name\":\"_addressList\",\"type\":\"address[]\"},{\"internalType\":\"uint256\",\"name\":\"_addressCount\",\"type\":\"uint256\"},{\"internalType\":\"bytes[]\",\"name\":\"sig\",\"type\":\"bytes[]\"}],\"name\":\"setAbiterList\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return err
	}
	log.Info("SetArbiterList", "arbiters", len(arbiters), "selfAccount", w.account.PublicKey())

	gasPrice, err := w.client.GasPrice()
	if err != nil {
		return err
	}
	count := big.NewInt(int64(totalCount))
	input, err := a.Pack("setAbiterList", arbiters, &count, signature)
	if err != nil {
		return err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input, GasPrice: gasPrice}

	gasLimit, err := w.client.EstimateGasLimit(context.TODO(), msg)
	if err != nil {
		return err
	}
	if gasLimit == 0 {
		return errors.New("SetArbiterList EstimateGasLimit is 0")
	}
	w.client.LockNonce()
	defer w.client.UnlockNonce()
	n, err := w.client.GetNonce()
	if err != nil {
		return err
	}

	tx := evmtransaction.NewTransaction(n.Uint64(), bridge, big.NewInt(0), gasLimit, gasPrice, input)
	hash, err := w.client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}
	log.Info("SetArbiterList", "error", err, "hash", hash.String())
	return err
}

func (w *EVMVoter) GetArbiterList(bridgeAddress string) ([]common.Address, error) {
	definition := "[{\"inputs\":[],\"name\":\"getAbiterList\",\"outputs\":[{\"internalType\":\"address[]\",\"name\":\"\",\"type\":\"address[]\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	a, err := abi.JSON(strings.NewReader(definition))
	if err != nil {
		return []common.Address{}, err
	}
	input, err := a.Pack("getAbiterList")
	if err != nil {
		return []common.Address{}, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err:= w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("GetArbiterList", "error", err, "out", out)

	out0 := make([]common.Address, 0)
	err = a.Unpack(&out0, "getAbiterList", out)
	if err != nil {
		return nil, err
	}
	return out0, err
}

func (w *EVMVoter) IsDeployedBridgeContract(bridgeAddress string) bool {
	return w.client.IsContractAddress(bridgeAddress)
}

func (w *EVMVoter) GetClient() ChainClient {
	return w.client
}

func (w *EVMVoter) SignData(data []byte) []byte {
	privateKey := w.account.PrivateKey()
	sign, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil
	}
	return sign
}
