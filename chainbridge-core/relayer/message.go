// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package relayer

import "github.com/elastos/Elastos.ELA.SideChain.ESC/common"

type TransferType string

const (
	FungibleTransfer    TransferType = "FungibleTransfer"
	NonFungibleTransfer TransferType = "NonFungibleTransfer"
	GenericTransfer     TransferType = "GenericTransfer"
)

type ProposalStatus uint8

const (
	ProposalStatusInactive ProposalStatus = 0
	ProposalStatusActive   ProposalStatus = 1
	ProposalStatusPassed   ProposalStatus = 2 // Ready to be executed
	ProposalStatusExecuted ProposalStatus = 3
	ProposalStatusCanceled ProposalStatus = 4
)

var (
	StatusMap = map[ProposalStatus]string{ProposalStatusInactive: "inactive", ProposalStatusActive: "active", ProposalStatusPassed: "passed", ProposalStatusExecuted: "executed", ProposalStatusCanceled: "canceled"}
)

type Message struct {
	Source       uint8  // Source where message was initiated
	Destination  uint8  // Destination chain of message
	DepositNonce uint64 // Nonce for the deposit
	ResourceId   [32]byte
	Payload      []interface{} // data associated with event sequence
}

type ChangeSuperSigner struct {
	SourceChain    uint8
	OldSuperSigner common.Address
	NewSuperSigner common.Address
	NodePublicKey  string
}

type ProposalEvent struct {
	SourceChain  uint8
	DepositNonce uint64
	Status       ProposalStatus
	ResourceId   [32]byte
	DataHash     [32]byte
}