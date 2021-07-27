// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"context"
	"math/big"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/dpos_msg"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/relayer"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
)

var BlockRetryInterval = time.Second * 5

type ChainClient interface {
	LatestBlock() (*big.Int, error)
	SignAndSendTransaction(ctx context.Context, tx evmclient.CommonTransaction) (common.Hash, error)
	RelayerAddress() common.Address
	CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error)
	UnsafeNonce() (*big.Int, error)
	LockNonce()
	UnlockNonce()
	UnsafeIncreaseNonce() error
	GasPrice() (*big.Int, error)
	ChainID(ctx context.Context) (*big.Int, error)
	Engine() engine.ESCEngine
}

type Proposer interface {
	//Status(client ChainClient) (relayer.ProposalStatus, error)
	//VotedBy(client ChainClient, by common.Address) (bool, error)
	Execute(client ChainClient) error
	//Vote(client ChainClient) error
}

type MessageHandler interface {
	HandleMessage(m *relayer.Message) (Proposer, error)
}

type EVMVoter struct {
	stop   <-chan struct{}
	mh     MessageHandler
	client ChainClient
	account *secp256k1.Keypair
}

func NewVoter(mh MessageHandler, client ChainClient, arbiterAccount *secp256k1.Keypair) *EVMVoter {
	return &EVMVoter{
		mh:     mh,
		client: client,
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
	msg.SourceChainID = proposal.Source
	msg.DestChainID = proposal.Destination
	msg.DepositNonce = proposal.DepositNonce
	copy(msg.ResourceId[:], proposal.ResourceId[:])
	msg.Data = proposal.Data

	msg.Proposer, _ = hexutil.Decode(w.account.PublicKey())
	msg.Signature = w.SignData(proposal.Hash().Bytes())
	w.client.Engine().SendMsgProposal(msg)
	return msg.GetHash()
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
