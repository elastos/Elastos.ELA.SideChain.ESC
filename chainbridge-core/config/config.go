// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/bridgelog"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
)

var (
	DefaultConfigDir    = "./chainbridge/config/chain_bridge.json"
	KeystoreFlagName    = "./data/keystore/"
	BlockstoreFlagName  = "./chainbridge/blockstore"
	FreshStartFlagName  = "fresh"
	LatestBlockFlagName = "latest"
)

type GeneralChainConfig struct {
	Name           string `json:"name"`     // Human-readable chain name
	Id             uint64 `json:"id"`       //ChainID
	Endpoint       string `json:"endpoint"` // url for rpc endpoint
	From           string `json:"from"`     // address of key to use
	KeystorePath   string // Location of key files
	Insecure       bool   // Indicated whether the test keyring should be used
	BlockstorePath string // Location of blockstore
	FreshStart     bool   // If true, blockstore is ignored at start.
	LatestBlock    bool   // If true, overrides blockstore or latest block in config and starts from current block
	Opts           OpsConfig
	Kp             *secp256k1.Keypair
}

func (c *GeneralChainConfig) Validate() error {
	// viper defaults to 0 for not specified ints, but we must have a valid chain id
	// Previous method of checking used a string cast like below
	//chainId := string(c.Id)
	if c.Id == 0 {
		return fmt.Errorf("required field chain.Id empty for chain %v", c.Id)
	}
	if c.Endpoint == "" {
		return fmt.Errorf("required field chain.Endpoint empty for chain %v", c.Id)
	}
	if c.Name == "" {
		return fmt.Errorf("required field chain.Name empty for chain %v", c.Id)
	}
	if err := c.Opts.Validate(); err != nil {
		return err
	}
	return nil
}

type BridgeConfig struct {
	Chains []GeneralChainConfig `json:"chains"`
}

func NewConfig() *BridgeConfig {
	return &BridgeConfig{
		Chains: []GeneralChainConfig{},
	}
}

func (c *BridgeConfig) validateAndParse() error {
	for _, chain := range c.Chains {
		err := chain.Validate()
		if err != nil {
			return err
		}
		ops, err := chain.Opts.ParseConfig()
		if err != nil {
			return err
		}
		chain.Opts = *ops
	}
	return nil
}

func GetConfig(path string) (*BridgeConfig, error) {
	var fig = NewConfig()
	if path == "" {
		path = DefaultConfigDir
	}

	err := loadConfig(path, fig)
	if err != nil {
		bridgelog.Warn("err loading json file", "err", err.Error())
		return fig, err
	}

	err = fig.validateAndParse()
	if err != nil {
		return nil, err
	}
	return fig, nil
}

func loadConfig(file string, config *BridgeConfig) error {
	ext := filepath.Ext(file)
	fp, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	f, err := os.Open(filepath.Clean(fp))
	if err != nil {
		return err
	}

	if ext == ".json" {
		if err = json.NewDecoder(f).Decode(&config); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unrecognized extention: %s", ext)
	}
	return nil
}
