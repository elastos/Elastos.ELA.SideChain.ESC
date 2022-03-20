// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmtransaction"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge_abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
)

type ChainClient interface {
	LatestBlock() (*big.Int, error)
	CurrentBlock() (*types.Block, error)
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

type EVMVoter struct {
	stop    <-chan struct{}
	client  ChainClient
	account *secp256k1.Keypair
}

func NewVoter(client ChainClient, arbiterAccount *secp256k1.Keypair) *EVMVoter {
	return &EVMVoter{
		client:  client,
		account: arbiterAccount,
	}
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
	from := w.client.GetClientAddress()
	msg := ethereum.CallMsg{From: from, To: &bridge, Data: input, GasPrice: gasPrice}
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
	a, err := chainbridge_abi.GetArbitersABI()
	if err != nil {
		return []common.Address{}, err
	}
	input, err := a.Pack("getAbiterList")
	if err != nil {
		return []common.Address{}, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("GetArbiterList", "error", err, "out", out)

	out0 := make([]common.Address, 0)
	err = a.Unpack(&out0, "getAbiterList", out)
	if err != nil {
		return []common.Address{}, err
	}
	return out0, err
}

func (w *EVMVoter) GetSignatures(bridgeAddress string) ([][crypto.SignatureLength]byte, error) {
	a, err := chainbridge_abi.GetSignaturesABI()
	if err != nil {
		return [][crypto.SignatureLength]byte{}, err
	}
	input, err := a.Pack("getAbiterSigs")
	if err != nil {
		return [][crypto.SignatureLength]byte{}, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("getAbiterSigs", "error", err, "out", out)

	out0 := make([][crypto.SignatureLength]byte, 0)
	err = a.Unpack(&out0, "getAbiterSigs", out)
	if err != nil {
		return [][crypto.SignatureLength]byte{}, err
	}
	return out0, err
}

func (w *EVMVoter) GetTotalCount(bridgeAddress string) (uint64, error) {
	a, err := chainbridge_abi.GetTotalCountABI()
	if err != nil {
		return 0, err
	}
	input, err := a.Pack("getAbiterCount")
	if err != nil {
		return 0, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("getAbiterCount", "error", err, "out", out)

	out0 := big.NewInt(0).SetBytes(out)
	err = a.Unpack(&out0, "getAbiterCount", out)
	if err != nil {
		return 0, err
	}
	return out0.Uint64(), err
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
