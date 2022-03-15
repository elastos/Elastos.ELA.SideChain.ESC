// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package evmclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/config"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/keystore"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge_abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/ethclient"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rpc"
)

type EVMClient struct {
	*ethclient.Client
	rpClient  *rpc.Client
	nonceLock sync.Mutex
	config    *config.GeneralChainConfig
	nonce     *big.Int

	engine               engine.ESCEngine
	depositRecordABI     abi.ABI
	depositRecordNFTABI  abi.ABI
	changeSuperSignerABI abi.ABI
	proposalEventABI     abi.ABI
}

type CommonTransaction interface {
	// Hash returns the transaction hash.
	Hash() common.Hash
	// Returns signed transaction by provided private key
	RawWithSignature(key *ecdsa.PrivateKey, chainID *big.Int) ([]byte, error)
}

func NewEVMClient(engine engine.ESCEngine) *EVMClient {
	abi, err := chainbridge_abi.GetDepositRecordABI()
	if err != nil {
		return nil
	}
	changeSuperSignerABI, err := chainbridge_abi.GetChangeSuperSignerABI()
	if err != nil {
		return nil
	}
	proposalEvt, err := chainbridge_abi.ProposalEventABI()
	if err != nil {
		return nil
	}
	nftRecord, err := chainbridge_abi.GetDepositNFTRecordABI()
	if err != nil {
		return nil
	}
	client := &EVMClient{engine: engine, depositRecordABI: abi, changeSuperSignerABI: changeSuperSignerABI}
	client.proposalEventABI = proposalEvt
	client.depositRecordNFTABI = nftRecord
	return client
}

func (c *EVMClient) Configurate(generalConfig *config.GeneralChainConfig, accountPath, password string) error {
	if generalConfig == nil {
		return errors.New("chain config is nil")
	}
	c.config = generalConfig
	if len(generalConfig.KeystorePath) > 0 {
		accountPath = generalConfig.KeystorePath
	}
	kp, err := keystore.KeypairFromAddress(keystore.EthChain, accountPath, []byte(password), generalConfig.Insecure)
	if err == nil {
		krp := kp.(*secp256k1.Keypair)
		c.config.Kp = krp
	}
	rpcClient, err := rpc.DialContext(context.TODO(), generalConfig.Endpoint)
	if err != nil {
		return err
	}
	c.Client = ethclient.NewClient(rpcClient)
	c.rpClient = rpcClient

	if generalConfig.LatestBlock {
		curr, err := c.LatestBlock()
		if err != nil {
			return err
		}
		generalConfig.Opts.StartBlock = curr.Uint64()
	}
	return nil
}

type headerNumber struct {
	Number *big.Int `json:"number"           gencodec:"required"`
}

func (h *headerNumber) UnmarshalJSON(input []byte) error {
	type headerNumber struct {
		Number *hexutil.Big `json:"number" gencodec:"required"`
	}
	var dec headerNumber
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Number == nil {
		return errors.New("missing required field 'number' for Header")
	}
	h.Number = (*big.Int)(dec.Number)
	return nil
}

// LatestBlock returns the latest block from the current chain
func (c *EVMClient) LatestBlock() (*big.Int, error) {
	var head *headerNumber

	err := c.rpClient.CallContext(context.Background(), &head, "eth_getBlockByNumber", toBlockNumArg(nil), false)
	if err == nil && head == nil {
		err = ethereum.NotFound
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return head.Number, err
}

func (c *EVMClient) CurrentBlock() (*types.Block, error) {
	return c.Client.BlockByNumber(context.Background(), nil)
}

func (c *EVMClient) Engine() engine.ESCEngine {
	return c.engine
}

func (c *EVMClient) GetClientAddress() common.Address {
	return common.HexToAddress(c.config.Kp.Address())
}

const (
	//DepositSignature string = "Deposit(uint8,bytes32,uint64)"
	DepositRecord     string = "DepositRecordERC20OrWETH(address,uint64,bytes32,uint64,address,uint256,uint256)"
	DepositNFTRecord  string = "DepositRecordERC721(address,uint64,bytes32,uint64,address,uint256,bytes,uint256)"
	ChangeSuperSigner string = "ChangeSuperSigner(address,address,bytes)"
	ProposalEvent     string = "ProposalEvent(uint64,uint64,uint8,bytes32,bytes32)"
)

// SendRawTransaction accepts rlp-encode of signed transaction and sends it via RPC call
func (c *EVMClient) SendRawTransaction(ctx context.Context, tx []byte) error {
	return c.rpClient.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(tx))
}

func (c *EVMClient) CallContract(ctx context.Context, callArgs map[string]interface{}, blockNumber *big.Int) ([]byte, error) {
	var hex hexutil.Bytes
	err := c.rpClient.CallContext(ctx, &hex, "eth_call", callArgs, toBlockNumArg(blockNumber))
	if err != nil {
		return nil, err
	}
	return hex, nil
}

func (c *EVMClient) PendingCallContract(ctx context.Context, callArgs map[string]interface{}) ([]byte, error) {
	var hex hexutil.Bytes
	err := c.rpClient.CallContext(ctx, &hex, "eth_call", callArgs, "pending")
	if err != nil {
		return nil, err
	}
	return hex, nil
}

func (c *EVMClient) SignAndSendTransaction(ctx context.Context, tx CommonTransaction) (common.Hash, error) {
	id, err := c.ChainID(ctx)
	if err != nil {
		panic(err)
	}
	rawTX, err := tx.RawWithSignature(c.config.Kp.PrivateKey(), id)
	if err != nil {
		return common.Hash{}, err
	}

	err = c.SendRawTransaction(ctx, rawTX)
	if err != nil {
		fmt.Println("send account", "account", c.config.Kp.Address())
		return common.Hash{}, err
	}
	return tx.Hash(), nil
}

func (c *EVMClient) LockNonce() {
	c.nonceLock.Lock()
}

func (c *EVMClient) UnlockNonce() {
	c.nonceLock.Unlock()
}

func (c *EVMClient) GetNonce() (*big.Int, error) {
	var err error
	for i := 0; i <= 10; i++ {
		nonce, err := c.PendingNonceAt(context.Background(), c.config.Kp.CommonAddress())
		if err != nil {
			time.Sleep(1)
			continue
		}
		c.nonce = big.NewInt(0).SetUint64(nonce)
		return c.nonce, nil
	}
	return nil, err
}

func (c *EVMClient) GasPrice() (*big.Int, error) {
	gasPrice, err := c.SafeEstimateGasPrice(context.TODO())
	if err != nil {
		return nil, err
	}
	return gasPrice, nil
}

func (c *EVMClient) SafeEstimateGasPrice(ctx context.Context) (*big.Int, error) {
	suggestedGasPrice, err := c.SuggestGasPrice(context.TODO())
	if err != nil {
		return nil, err
	}

	gasPrice := multiplyGasPrice(suggestedGasPrice, big.NewFloat(c.config.Opts.GasMultiplier))

	// Check we aren't exceeding our limit

	if gasPrice.Cmp(big.NewInt(0).SetUint64(c.config.Opts.MaxGasPrice)) == 1 {
		return big.NewInt(0).SetUint64(c.config.Opts.MaxGasPrice), nil
	} else {
		return gasPrice, nil
	}
}

func (c *EVMClient) EstimateGasLimit(ctx context.Context, msg ethereum.CallMsg) (uint64, error) {
	gasLimit, err := c.EstimateGas(ctx, msg)
	if err != nil {
		return 0, err
	}
	gas := multiplyGasPrice(big.NewInt(0).SetUint64(gasLimit), big.NewFloat(c.config.Opts.GasMultiplier))
	if gas.Cmp(big.NewInt(0).SetUint64(c.config.Opts.GasLimit)) == 1 {
		return big.NewInt(0).SetUint64(c.config.Opts.GasLimit).Uint64(), nil
	}
	return gas.Uint64(), nil
}

func multiplyGasPrice(gasEstimate *big.Int, gasMultiplier *big.Float) *big.Int {

	gasEstimateFloat := new(big.Float).SetInt(gasEstimate)

	result := gasEstimateFloat.Mul(gasEstimateFloat, gasMultiplier)

	gasPrice := new(big.Int)

	result.Int(gasPrice)

	return gasPrice
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	return hexutil.EncodeBig(number)
}

// buildQuery constructs a query for the bridgeContract by hashing sig to get the event topic
func buildQuery(contract common.Address, sig string, startBlock *big.Int, endBlock *big.Int) ethereum.FilterQuery {
	query := ethereum.FilterQuery{
		FromBlock: startBlock,
		ToBlock:   endBlock,
		Addresses: []common.Address{contract},
		Topics: [][]common.Hash{
			{crypto.Keccak256Hash([]byte(sig))},
		},
	}
	return query
}

func (c *EVMClient) GetConfig() *config.GeneralChainConfig {
	return c.config
}

func (c *EVMClient) IsContractAddress(address string) bool {
	code, err := c.CodeAt(context.TODO(), common.HexToAddress(address), nil)
	if err != nil || len(code) == 0 {
		return false
	}
	return true
}
