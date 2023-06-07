// Copyright 2019 The Elastos.ELA.SideChain.ESC Authors
// This file is part of the Elastos.ELA.SideChain.ESC library.
//
// The Elastos.ELA.SideChain.ESC library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Elastos.ELA.SideChain.ESC library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Elastos.ELA.SideChain.ESC library. If not, see <http://www.gnu.org/licenses/>.

package bind_test

import (
	"bytes"
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ESC"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi/bind"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/hexutil"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
)

type mockCaller struct {
	codeAtBlockNumber       *big.Int
	callContractBlockNumber *big.Int

	codeAtBytes []byte
}

func (mc *mockCaller) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	mc.codeAtBlockNumber = blockNumber
	return []byte{1, 2, 3}, nil
}

func (mc *mockCaller) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	mc.callContractBlockNumber = blockNumber
	return nil, nil
}

type mockPendingCaller struct {
	*mockCaller
	pendingCodeAtBytes        []byte
	pendingCodeAtErr          error
	pendingCodeAtCalled       bool
	pendingCallContractCalled bool
	pendingCallContractBytes  []byte
	pendingCallContractErr    error
}

func (mc *mockPendingCaller) PendingCodeAt(ctx context.Context, contract common.Address) ([]byte, error) {
	mc.pendingCodeAtCalled = true
	return mc.pendingCodeAtBytes, mc.pendingCodeAtErr
}

func (mc *mockPendingCaller) PendingCallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error) {
	mc.pendingCallContractCalled = true
	return mc.pendingCallContractBytes, mc.pendingCallContractErr
}

func TestPassingBlockNumber(t *testing.T) {

	//mc := &mockCaller{}
	mc := &mockPendingCaller{
		mockCaller: &mockCaller{
			codeAtBytes: []byte{1, 2, 3},
		},
	}

	bc := bind.NewBoundContract(common.HexToAddress("0x0"), abi.ABI{
		Methods: map[string]abi.Method{
			"something": {
				Name:    "something",
				Outputs: abi.Arguments{},
			},
		},
	}, mc, nil, nil)

	blockNumber := big.NewInt(42)

	bc.Call(&bind.CallOpts{BlockNumber: blockNumber}, nil, "something")

	if mc.callContractBlockNumber != blockNumber {
		t.Fatalf("CallContract() was not passed the block number")
	}

	if mc.codeAtBlockNumber != blockNumber {
		t.Fatalf("CodeAt() was not passed the block number")
	}

	bc.Call(&bind.CallOpts{}, nil, "something")

	if mc.callContractBlockNumber != nil {
		t.Fatalf("CallContract() was passed a block number when it should not have been")
	}

	if mc.codeAtBlockNumber != nil {
		t.Fatalf("CodeAt() was passed a block number when it should not have been")
	}
	bc.Call(&bind.CallOpts{BlockNumber: blockNumber, Pending: true}, nil, "something")

	if !mc.pendingCallContractCalled {
		t.Fatalf("CallContract() was not passed the block number")
	}

	if !mc.pendingCodeAtCalled {
		t.Fatalf("CodeAt() was not passed the block number")
	}

}

const hexData = "0x000000000000000000000000376c47978271565f56deb45495afa69e59c16ab200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000158"

func TestUnpackIndexedStringTyLogIntoMap(t *testing.T) {
	hash := crypto.Keccak256Hash([]byte("testName"))
	mockLog := types.Log{
		Address: common.HexToAddress("0x0"),
		Topics: []common.Hash{
			crypto.Keccak256Hash([]byte("received(string,address,uint256,bytes)")),
			hash,
		},
		Data:        hexutil.MustDecode(hexData),
		BlockNumber: uint64(26),
		TxHash:      common.HexToHash("0x0"),
		TxIndex:     111,
		BlockHash:   common.BytesToHash([]byte{1, 2, 3, 4, 5}),
		Index:       7,
		Removed:     false,
	}

	abiString := `[{"anonymous":false,"inputs":[{"indexed":true,"name":"name","type":"string"},{"indexed":false,"name":"sender","type":"address"},{"indexed":false,"name":"amount","type":"uint256"},{"indexed":false,"name":"memo","type":"bytes"}],"name":"received","type":"event"}]`
	parsedAbi, _ := abi.JSON(strings.NewReader(abiString))
	bc := bind.NewBoundContract(common.HexToAddress("0x0"), parsedAbi, nil, nil, nil)

	receivedMap := make(map[string]interface{})
	expectedReceivedMap := map[string]interface{}{
		"name":   hash,
		"sender": common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2"),
		"amount": big.NewInt(1),
		"memo":   []byte{88},
	}
	if err := bc.UnpackLogIntoMap(receivedMap, "received", mockLog); err != nil {
		t.Error(err)
	}

	if len(receivedMap) != 4 {
		t.Fatal("unpacked map expected to have length 4")
	}
	if receivedMap["name"] != expectedReceivedMap["name"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["sender"] != expectedReceivedMap["sender"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["amount"].(*big.Int).Cmp(expectedReceivedMap["amount"].(*big.Int)) != 0 {
		t.Error("unpacked map does not match expected map")
	}
	if !bytes.Equal(receivedMap["memo"].([]byte), expectedReceivedMap["memo"].([]byte)) {
		t.Error("unpacked map does not match expected map")
	}
}

func TestUnpackIndexedSliceTyLogIntoMap(t *testing.T) {
	sliceBytes, err := rlp.EncodeToBytes([]string{"name1", "name2", "name3", "name4"})
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.Keccak256Hash(sliceBytes)
	mockLog := types.Log{
		Address: common.HexToAddress("0x0"),
		Topics: []common.Hash{
			crypto.Keccak256Hash([]byte("received(string[],address,uint256,bytes)")),
			hash,
		},
		Data:        hexutil.MustDecode(hexData),
		BlockNumber: uint64(26),
		TxHash:      common.HexToHash("0x0"),
		TxIndex:     111,
		BlockHash:   common.BytesToHash([]byte{1, 2, 3, 4, 5}),
		Index:       7,
		Removed:     false,
	}

	abiString := `[{"anonymous":false,"inputs":[{"indexed":true,"name":"names","type":"string[]"},{"indexed":false,"name":"sender","type":"address"},{"indexed":false,"name":"amount","type":"uint256"},{"indexed":false,"name":"memo","type":"bytes"}],"name":"received","type":"event"}]`
	parsedAbi, _ := abi.JSON(strings.NewReader(abiString))
	bc := bind.NewBoundContract(common.HexToAddress("0x0"), parsedAbi, nil, nil, nil)

	receivedMap := make(map[string]interface{})
	expectedReceivedMap := map[string]interface{}{
		"names":  hash,
		"sender": common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2"),
		"amount": big.NewInt(1),
		"memo":   []byte{88},
	}
	if err := bc.UnpackLogIntoMap(receivedMap, "received", mockLog); err != nil {
		t.Error(err)
	}

	if len(receivedMap) != 4 {
		t.Fatal("unpacked map expected to have length 4")
	}
	if receivedMap["names"] != expectedReceivedMap["names"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["sender"] != expectedReceivedMap["sender"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["amount"].(*big.Int).Cmp(expectedReceivedMap["amount"].(*big.Int)) != 0 {
		t.Error("unpacked map does not match expected map")
	}
	if !bytes.Equal(receivedMap["memo"].([]byte), expectedReceivedMap["memo"].([]byte)) {
		t.Error("unpacked map does not match expected map")
	}
}

func TestUnpackIndexedArrayTyLogIntoMap(t *testing.T) {
	arrBytes, err := rlp.EncodeToBytes([2]common.Address{common.HexToAddress("0x0"), common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2")})
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.Keccak256Hash(arrBytes)
	mockLog := types.Log{
		Address: common.HexToAddress("0x0"),
		Topics: []common.Hash{
			crypto.Keccak256Hash([]byte("received(address[2],address,uint256,bytes)")),
			hash,
		},
		Data:        hexutil.MustDecode(hexData),
		BlockNumber: uint64(26),
		TxHash:      common.HexToHash("0x0"),
		TxIndex:     111,
		BlockHash:   common.BytesToHash([]byte{1, 2, 3, 4, 5}),
		Index:       7,
		Removed:     false,
	}

	abiString := `[{"anonymous":false,"inputs":[{"indexed":true,"name":"addresses","type":"address[2]"},{"indexed":false,"name":"sender","type":"address"},{"indexed":false,"name":"amount","type":"uint256"},{"indexed":false,"name":"memo","type":"bytes"}],"name":"received","type":"event"}]`
	parsedAbi, _ := abi.JSON(strings.NewReader(abiString))
	bc := bind.NewBoundContract(common.HexToAddress("0x0"), parsedAbi, nil, nil, nil)

	receivedMap := make(map[string]interface{})
	expectedReceivedMap := map[string]interface{}{
		"addresses": hash,
		"sender":    common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2"),
		"amount":    big.NewInt(1),
		"memo":      []byte{88},
	}
	if err := bc.UnpackLogIntoMap(receivedMap, "received", mockLog); err != nil {
		t.Error(err)
	}

	if len(receivedMap) != 4 {
		t.Fatal("unpacked map expected to have length 4")
	}
	if receivedMap["addresses"] != expectedReceivedMap["addresses"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["sender"] != expectedReceivedMap["sender"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["amount"].(*big.Int).Cmp(expectedReceivedMap["amount"].(*big.Int)) != 0 {
		t.Error("unpacked map does not match expected map")
	}
	if !bytes.Equal(receivedMap["memo"].([]byte), expectedReceivedMap["memo"].([]byte)) {
		t.Error("unpacked map does not match expected map")
	}
}

func TestUnpackIndexedFuncTyLogIntoMap(t *testing.T) {
	mockAddress := common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2")
	addrBytes := mockAddress.Bytes()
	hash := crypto.Keccak256Hash([]byte("mockFunction(address,uint)"))
	functionSelector := hash[:4]
	functionTyBytes := append(addrBytes, functionSelector...)
	var functionTy [24]byte
	copy(functionTy[:], functionTyBytes[0:24])
	mockLog := types.Log{
		Address: common.HexToAddress("0x0"),
		Topics: []common.Hash{
			crypto.Keccak256Hash([]byte("received(function,address,uint256,bytes)")),
			common.BytesToHash(functionTyBytes),
		},
		Data:        hexutil.MustDecode(hexData),
		BlockNumber: uint64(26),
		TxHash:      common.HexToHash("0x5c698f13940a2153440c6d19660878bc90219d9298fdcf37365aa8d88d40fc42"),
		TxIndex:     111,
		BlockHash:   common.BytesToHash([]byte{1, 2, 3, 4, 5}),
		Index:       7,
		Removed:     false,
	}

	abiString := `[{"anonymous":false,"inputs":[{"indexed":true,"name":"function","type":"function"},{"indexed":false,"name":"sender","type":"address"},{"indexed":false,"name":"amount","type":"uint256"},{"indexed":false,"name":"memo","type":"bytes"}],"name":"received","type":"event"}]`
	parsedAbi, _ := abi.JSON(strings.NewReader(abiString))
	bc := bind.NewBoundContract(common.HexToAddress("0x0"), parsedAbi, nil, nil, nil)

	receivedMap := make(map[string]interface{})
	expectedReceivedMap := map[string]interface{}{
		"function": functionTy,
		"sender":   common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2"),
		"amount":   big.NewInt(1),
		"memo":     []byte{88},
	}
	if err := bc.UnpackLogIntoMap(receivedMap, "received", mockLog); err != nil {
		t.Error(err)
	}

	if len(receivedMap) != 4 {
		t.Fatal("unpacked map expected to have length 4")
	}
	if receivedMap["function"] != expectedReceivedMap["function"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["sender"] != expectedReceivedMap["sender"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["amount"].(*big.Int).Cmp(expectedReceivedMap["amount"].(*big.Int)) != 0 {
		t.Error("unpacked map does not match expected map")
	}
	if !bytes.Equal(receivedMap["memo"].([]byte), expectedReceivedMap["memo"].([]byte)) {
		t.Error("unpacked map does not match expected map")
	}
}

func TestUnpackIndexedBytesTyLogIntoMap(t *testing.T) {
	byts := []byte{1, 2, 3, 4, 5}
	hash := crypto.Keccak256Hash(byts)
	mockLog := types.Log{
		Address: common.HexToAddress("0x0"),
		Topics: []common.Hash{
			crypto.Keccak256Hash([]byte("received(bytes,address,uint256,bytes)")),
			hash,
		},
		Data:        hexutil.MustDecode(hexData),
		BlockNumber: uint64(26),
		TxHash:      common.HexToHash("0x5c698f13940a2153440c6d19660878bc90219d9298fdcf37365aa8d88d40fc42"),
		TxIndex:     111,
		BlockHash:   common.BytesToHash([]byte{1, 2, 3, 4, 5}),
		Index:       7,
		Removed:     false,
	}

	abiString := `[{"anonymous":false,"inputs":[{"indexed":true,"name":"content","type":"bytes"},{"indexed":false,"name":"sender","type":"address"},{"indexed":false,"name":"amount","type":"uint256"},{"indexed":false,"name":"memo","type":"bytes"}],"name":"received","type":"event"}]`
	parsedAbi, _ := abi.JSON(strings.NewReader(abiString))
	bc := bind.NewBoundContract(common.HexToAddress("0x0"), parsedAbi, nil, nil, nil)

	receivedMap := make(map[string]interface{})
	expectedReceivedMap := map[string]interface{}{
		"content": hash,
		"sender":  common.HexToAddress("0x376c47978271565f56DEB45495afa69E59c16Ab2"),
		"amount":  big.NewInt(1),
		"memo":    []byte{88},
	}
	if err := bc.UnpackLogIntoMap(receivedMap, "received", mockLog); err != nil {
		t.Error(err)
	}

	if len(receivedMap) != 4 {
		t.Fatal("unpacked map expected to have length 4")
	}
	if receivedMap["content"] != expectedReceivedMap["content"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["sender"] != expectedReceivedMap["sender"] {
		t.Error("unpacked map does not match expected map")
	}
	if receivedMap["amount"].(*big.Int).Cmp(expectedReceivedMap["amount"].(*big.Int)) != 0 {
		t.Error("unpacked map does not match expected map")
	}
	if !bytes.Equal(receivedMap["memo"].([]byte), expectedReceivedMap["memo"].([]byte)) {
		t.Error("unpacked map does not match expected map")
	}
}
