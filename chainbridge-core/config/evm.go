// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package config

import (
	"fmt"
)

const DefaultGasLimit = 7000000
const DefaultGasPrice = 20000000000
const DefaultGasMultiplier = 1.1
const DefaultBlockConfirmations = 10

type OpsConfig struct {
	Bridge             string  `mapstructure:"bridge"`
	MaxGasPrice        uint64  `mapstructure:"maxGasPrice"`
	GasMultiplier      float64 `mapstructure:"gasMultiplier"`
	GasLimit           uint64  `mapstructure:"gasLimit"`
	StartBlock         uint64  `mapstructure:"startBlock"`
	BlockConfirmations int64   `mapstructure:"blockConfirmations"`
}

func (c *OpsConfig) Validate() error {
	if c.Bridge == "" {
		return fmt.Errorf("required field chain.Bridge empty for chain")
	}
	return nil
}

func (c *OpsConfig) ParseConfig() (*OpsConfig, error) {
	config := &OpsConfig{}

	if c.Bridge != "" {
		config.Bridge = c.Bridge
	} else {
		return nil, fmt.Errorf("must provide opts.bridge field for ethereum config")
	}

	if c.GasLimit != 0 {
		config.GasLimit = c.GasLimit
	} else {
		config.GasLimit = DefaultGasLimit
	}

	if c.MaxGasPrice != 0 {
		config.MaxGasPrice = c.MaxGasPrice
	} else {
		config.MaxGasPrice = DefaultGasPrice
	}

	if c.GasMultiplier != 0 {
		config.GasMultiplier = c.GasMultiplier
	} else {
		config.GasMultiplier = DefaultGasMultiplier
	}

	if c.BlockConfirmations != 0 {
		config.BlockConfirmations = c.BlockConfirmations
	} else {
		config.BlockConfirmations = DefaultBlockConfirmations
	}

	config.StartBlock = c.StartBlock

	return config, nil
}
