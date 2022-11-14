// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package voter

import (
	"bytes"
	"context"
	"errors"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/chains/evm/evmtransaction"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge_abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/internal/ethapi"
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
	PendingTransaction() ([]ethapi.RPCTransaction, error)
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
	a, err := chainbridge_abi.GetSetArbitersABI()
	if err != nil {
		return err
	}
	gasPrice, err := w.client.GasPrice()
	if err != nil {
		log.Error("SetArbiterList GasPrice", "error", err)
		return err
	}
	count := big.NewInt(int64(totalCount))
	input, err := a.Pack("setArbiterList", arbiters, &count, signature)
	if err != nil {
		return err
	}
	pendingTx, _ := w.client.PendingTransaction()
	for _, tx := range pendingTx {
		if tx.To.String() == bridgeAddress && bytes.Compare(tx.Input, input) == 0 {
			bridgelog.Info("is pending tx")
			return nil
		}
	}

	bridge := common.HexToAddress(bridgeAddress)
	from := w.client.GetClientAddress()
	msg := ethereum.CallMsg{From: from, To: &bridge, Data: input, GasPrice: gasPrice}
	gasLimit, err := w.client.EstimateGasLimit(context.TODO(), msg)
	if err != nil {
		log.Error("SetArbiterList EstimateGasLimit", "error", err)
		return err
	}
	if gasLimit == 0 {
		return errors.New("SetArbiterList EstimateGasLimit is 0")
	}
	w.client.LockNonce()
	defer w.client.UnlockNonce()
	n, err := w.client.GetNonce()
	if err != nil {
		log.Error("SetArbiterList GetNonce", "error", err)
		return err
	}

	tx := evmtransaction.NewTransaction(n.Uint64(), bridge, big.NewInt(0), gasLimit, gasPrice, input)
	hash, err := w.client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		log.Error("SetArbiterList SignAndSendTransaction", "error", err)
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
	input, err := a.Pack("getArbiterList")
	if err != nil {
		return []common.Address{}, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("getArbiterList", "error", err, "out", out)

	out0 := make([]common.Address, 0)
	err = a.UnpackIntoInterface(&out0, "getArbiterList", out)
	if err != nil {
		return []common.Address{}, err
	}
	return out0, err
}

func (w *EVMVoter) SetESCState(bridgeAddress string, state uint8) error {
	gasPrice, err := w.client.GasPrice()
	if err != nil {
		return err
	}
	stateValue := big.NewInt(0).SetUint64(uint64(state))
	packData := common.LeftPadBytes(stateValue.Bytes(), 32)
	a, err := chainbridge_abi.SetESCStateABI()
	if err != nil {
		return err
	}
	khash := crypto.Keccak256(packData)
	signature := w.SignData(accounts.TextHash(khash))
	input, err := a.Pack("setChainStatus", state, signature)
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
		return errors.New("SetESCState EstimateGasLimit is 0")
	}
	w.client.LockNonce()
	defer w.client.UnlockNonce()
	n, err := w.client.GetNonce()
	if err != nil {
		return err
	}
	gasLimit = gasLimit * 3
	tx := evmtransaction.NewTransaction(n.Uint64(), bridge, big.NewInt(0), gasLimit, gasPrice, input)
	hash, err := w.client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}
	log.Info("SetESCState", "error", err, "hash", hash.String(), "gasLimit", gasLimit, "gasPrice", gasPrice)
	return err
}

func (w *EVMVoter) SetManualArbiter(bridgeAddress string, arbiters []common.Address, totalSigner int) error {
	gasPrice, err := w.client.GasPrice()
	if err != nil {
		return err
	}
	a, err := chainbridge_abi.SetManualArbiterABI()
	if err != nil {
		return err
	}

	data := make([]byte, 0)
	for _, arbiter := range arbiters {
		data = append(data, arbiter.Bytes()...)
	}
	totalCount := big.NewInt(0).SetUint64(uint64(totalSigner))
	totalBytes := common.LeftPadBytes(totalCount.Bytes(), 32)
	data = append(data, totalBytes...)
	khash := crypto.Keccak256(data)
	signature := w.SignData(accounts.TextHash(khash))
	input, err := a.Pack("setManualArbiter", arbiters, &totalCount, signature)
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
		return errors.New("setManualArbiter EstimateGasLimit is 0")
	}
	w.client.LockNonce()
	defer w.client.UnlockNonce()
	n, err := w.client.GetNonce()
	if err != nil {
		return err
	}
	gasLimit = gasLimit * 4
	tx := evmtransaction.NewTransaction(n.Uint64(), bridge, big.NewInt(0), gasLimit, gasPrice, input)
	hash, err := w.client.SignAndSendTransaction(context.TODO(), tx)
	if err != nil {
		return err
	}
	log.Info("setManualArbiter", "error", err, "hash", hash.String(), "gasLimit", gasLimit, "gasPrice", gasPrice)
	return err
}

func (w *EVMVoter) GetSignatures(bridgeAddress string) ([][crypto.SignatureLength]byte, error) {
	a, err := chainbridge_abi.GetSignaturesABI()
	if err != nil {
		return [][crypto.SignatureLength]byte{}, err
	}
	input, err := a.Pack("getArbiterSigs")
	if err != nil {
		return [][crypto.SignatureLength]byte{}, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("getArbiterSigs", "error", err, "out", out)

	out0 := make([][crypto.SignatureLength]byte, 0)
	err = a.UnpackIntoInterface(&out0, "getArbiterSigs", out)
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
	input, err := a.Pack("getArbiterCount")
	if err != nil {
		return 0, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("getArbiterCount", "error", err, "out", out)

	out0 := big.NewInt(0).SetBytes(out)
	err = a.UnpackIntoInterface(&out0, "getArbiterCount", out)
	if err != nil {
		return 0, err
	}
	return out0.Uint64(), err
}

func (w *EVMVoter) GetESCState(bridgeAddress string) (uint8, error) {
	a, err := chainbridge_abi.GetESCStateABI()
	if err != nil {
		return 0, err
	}
	input, err := a.Pack("getESCChainState")
	if err != nil {
		return 0, err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("GetESCState", "error", err, "out", out)

	out0 := big.NewInt(0).SetBytes(out)
	return uint8(out0.Uint64()), err
}

func (w *EVMVoter) GetHashSalt(bridgeAddress string) (*big.Int, error) {
	a, err := chainbridge_abi.GetHashSaltABI()
	if err != nil {
		return big.NewInt(0), err
	}
	input, err := a.Pack("GetHashSalt")
	if err != nil {
		return big.NewInt(0), err
	}
	bridge := common.HexToAddress(bridgeAddress)
	msg := ethereum.CallMsg{From: common.Address{}, To: &bridge, Data: input}
	out, err := w.client.CallContract(context.TODO(), toCallArg(msg), nil)
	log.Info("GetHashSalt", "error", err, "out", out)

	out0 := big.NewInt(0).SetBytes(out)
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
