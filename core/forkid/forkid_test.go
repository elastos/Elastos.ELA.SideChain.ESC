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

package forkid

import (
	"bytes"
	"math"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/rlp"
)

// TestCreation tests that different genesis and fork rule combinations result in
// the correct fork ID.
func TestCreation(t *testing.T) {
	type testcase struct {
		head uint64
		want ID
	}
	tests := []struct {
		config  *params.ChainConfig
		genesis common.Hash
		cases   []testcase
	}{
		// Mainnet test cases
		{
			params.MainnetChainConfig,
			params.MainnetGenesisHash,
			[]testcase{
				{0, ID{Hash: checksumToBytes(0xa58cf5fc), Next: 1}},              // Unsynced, last Frontier block
				{1, ID{Hash: checksumToBytes(0x5d123fc1), Next: 2}},              // First and last Homestead block
				{2, ID{Hash: checksumToBytes(0xed9684bd), Next: 3}},              // First and last Tangerine block
				{3, ID{Hash: checksumToBytes(0xd6fa7574), Next: 4}},              // First and last  Spurious block
				{4, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}},       // First Byzantium block
				{2426879, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}}, // Last Byzantium block
				{2426879, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}},       // First Constantinople, and Petersburg block
				{2426879, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}}, // Last Petersburg block
				{2426879, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}},       // Today Istanbul block
				{2426879, ID{Hash: checksumToBytes(0x46b9cb10), Next: 2426880}},      // Future Istanbul block
			},
		},
		// Ropsten test cases
		{
			params.TestnetChainConfig,
			params.TestnetGenesisHash,
			[]testcase{
				{0, ID{Hash: checksumToBytes(0x06623f46), Next: 1}},              // Unsynced, last Frontier block
				{1, ID{Hash: checksumToBytes(0x6980aadf), Next: 2}},              // First and last Homestead block
				{2, ID{Hash: checksumToBytes(0x3d585731), Next: 3}},              // First and last Tangerine block
				{3, ID{Hash: checksumToBytes(0xea52fca4), Next: 4}},              // First and last  Spurious block
				{4, ID{Hash: checksumToBytes(0xccb4d429), Next: 2333460}},       // First Byzantium block
				{2333459, ID{Hash: checksumToBytes(0xccb4d429), Next: 2333460}}, // Last Byzantium block
				{2333459, ID{Hash: checksumToBytes(0xccb4d429), Next: 2333460}}, // First Constantinople, and Petersburg block
				{2333459, ID{Hash: checksumToBytes(0xccb4d429), Next: 2333460}}, // Last Petersburg block
				{2333459, ID{Hash: checksumToBytes(0xccb4d429), Next: 2333460}},       // Today Istanbul block
				//{10000000, ID{Hash: checksumToBytes(0x879d6e30), Next: 0}},      // Future Istanbul block
			},
		},
		// Rinkeby test cases
		{
			params.RinkebyChainConfig,
			params.RinkebyGenesisHash,
			[]testcase{
				{0, ID{Hash: checksumToBytes(0xc070dcd1), Next: 1}},              // Unsynced, last Frontier block
				{1, ID{Hash: checksumToBytes(0x56c61556), Next: 2}},              // First and last Homestead block
				{2, ID{Hash: checksumToBytes(0x5d6130af), Next: 3}},              // First and last Tangerine block
				{3, ID{Hash: checksumToBytes(0x240e0924), Next: 4}},              // First and last  Spurious block
				{4, ID{Hash: checksumToBytes(0x84a0dabb), Next: 2208900}},       // First Byzantium block
				{2208899, ID{Hash: checksumToBytes(0x84a0dabb), Next: 2208900}}, // Last Byzantium block
				{2208899, ID{Hash: checksumToBytes(0x84a0dabb), Next: 2208900}},       // First Constantinople, and Petersburg block
				{2208899, ID{Hash: checksumToBytes(0x84a0dabb), Next: 2208900}}, // Last Petersburg block
				{2208899, ID{Hash: checksumToBytes(0x84a0dabb), Next: 2208900}},       // Today Istanbul block
				//{10000000, ID{Hash: checksumToBytes(0x879d6e30), Next: 0}},      // Future Istanbul block
			},
		},
		// Goerli test cases
		{
			params.GoerliChainConfig,
			params.GoerliGenesisHash,
			[]testcase{
				{0, ID{Hash: checksumToBytes(0xa3f5ab08), Next: 1}},       // Unsynced, last Frontier, Homestead, Tangerine, Spurious, Byzantium, Constantinople and first Petersburg block
				//{1561650, ID{Hash: checksumToBytes(0xa3f5ab08), Next: 1561651}}, // Last Petersburg block
				//{1561651, ID{Hash: checksumToBytes(0xc25efa5c), Next: 0}},       // First Istanbul block
				//{2000000, ID{Hash: checksumToBytes(0xc25efa5c), Next: 0}},       // Future Istanbul block
			},
		},
	}
	for i, tt := range tests {
		for j, ttt := range tt.cases {
			if have := newID(tt.config, tt.genesis, ttt.head); have != ttt.want {
				t.Errorf("test %d, case %d: fork ID mismatch: have %x, want %x", i, j, have, ttt.want)
			}
		}
	}
}

// TestValidation tests that a local peer correctly validates and accepts a remote
// fork ID.
func TestValidation(t *testing.T) {
	tests := []struct {
		head uint64
		id   ID
		err  error
	}{
		// Local is mainnet Petersburg, remote announces the same. No future fork is announced.
		//{7987396, ID{Hash: checksumToBytes(0x668db0af), Next: 0}, nil},

		// Local is mainnet Petersburg, remote announces the same. Remote also announces a next fork
		// at block 0xffffffff, but that is uncertain.
		//{7987396, ID{Hash: checksumToBytes(0x668db0af), Next: math.MaxUint64}, nil},

		// Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
		// also Byzantium, but it's not yet aware of Petersburg (e.g. non updated node before the fork).
		// In this case we don't know if Petersburg passed yet or not.
		{5, ID{Hash: checksumToBytes(0x46b9cb10), Next: 0}, nil},

		// Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
		// also Byzantium, and it's also aware of Petersburg (e.g. updated node before the fork). We
		// don't know if Petersburg passed yet (will pass) or not.
		{5, ID{Hash: checksumToBytes(0x46b9cb10), Next: 7280000}, nil},

		// Local is mainnet currently in Byzantium only (so it's aware of Petersburg), remote announces
		// also Byzantium, and it's also aware of some random fork (e.g. misconfigured Petersburg). As
		// neither forks passed at neither nodes, they may mismatch, but we still connect for now.
		{5, ID{Hash: checksumToBytes(0x46b9cb10), Next: math.MaxUint64}, nil},

		// Local is mainnet Petersburg, remote announces Byzantium + knowledge about Petersburg. Remote
		// is simply out of sync, accept.
		{5, ID{Hash: checksumToBytes(0x46b9cb10), Next: 7280000}, nil},

		// Local is mainnet Petersburg, remote announces Spurious + knowledge about Byzantium. Remote
		// is definitely out of sync. It may or may not need the Petersburg update, we don't know yet.
		//{7987396, ID{Hash: checksumToBytes(0x3edd5b10), Next: 4370000}, nil},
		//
		// Local is mainnet Byzantium, remote announces Petersburg. Local is out of sync, accept.
		//{7279999, ID{Hash: checksumToBytes(0x668db0af), Next: 0}, nil},

		// Local is mainnet Spurious, remote announces Byzantium, but is not aware of Petersburg. Local
		// out of sync. Local also knows about a future fork, but that is uncertain yet.
		//{4369999, ID{Hash: checksumToBytes(0xa00bc324), Next: 0}, nil},

		// Local is mainnet Petersburg. remote announces Byzantium but is not aware of further forks.
		// Remote needs software update.
		//{7987396, ID{Hash: checksumToBytes(0xa00bc324), Next: 0}, ErrRemoteStale},

		// Local is mainnet Petersburg, and isn't aware of more forks. Remote announces Petersburg +
		// 0xffffffff. Local needs software update, reject.
		//{7987396, ID{Hash: checksumToBytes(0x5cddc0e1), Next: 0}, ErrLocalIncompatibleOrStale},

		// Local is mainnet Byzantium, and is aware of Petersburg. Remote announces Petersburg +
		// 0xffffffff. Local needs software update, reject.
		{5, ID{Hash: checksumToBytes(0x5cddc0e1), Next: 0}, ErrLocalIncompatibleOrStale},

		// Local is mainnet Petersburg, remote is Rinkeby Petersburg.
		//{7987396, ID{Hash: checksumToBytes(0xafec6b27), Next: 0}, ErrLocalIncompatibleOrStale},

		// Local is mainnet Istanbul, far in the future. Remote announces Gopherium (non existing fork)
		// at some future block 88888888, for itself, but past block for local. Local is incompatible.
		//
		// This case detects non-upgraded nodes with majority hash power (typical Ropsten mess).
		//{88888888, ID{Hash: checksumToBytes(0x879d6e30), Next: 88888888}, ErrLocalIncompatibleOrStale},

		// Local is mainnet Byzantium. Remote is also in Byzantium, but announces Gopherium (non existing
		// fork) at block 5, before Petersburg. Local is incompatible.
		{5, ID{Hash: checksumToBytes(0x46b9cb10), Next: 5}, ErrLocalIncompatibleOrStale},
	}
	for i, tt := range tests {
		filter := newFilter(params.MainnetChainConfig, params.MainnetGenesisHash, func() uint64 { return tt.head })
		if err := filter(tt.id); err != tt.err {
			t.Errorf("test %d: validation error mismatch: have %v, want %v", i, err, tt.err)
		}
	}
}

// Tests that IDs are properly RLP encoded (specifically important because we
// use uint32 to store the hash, but we need to encode it as [4]byte).
func TestEncoding(t *testing.T) {
	tests := []struct {
		id   ID
		want []byte
	}{
		{ID{Hash: checksumToBytes(0), Next: 0}, common.Hex2Bytes("c6840000000080")},
		{ID{Hash: checksumToBytes(0xdeadbeef), Next: 0xBADDCAFE}, common.Hex2Bytes("ca84deadbeef84baddcafe,")},
		{ID{Hash: checksumToBytes(math.MaxUint32), Next: math.MaxUint64}, common.Hex2Bytes("ce84ffffffff88ffffffffffffffff")},
	}
	for i, tt := range tests {
		have, err := rlp.EncodeToBytes(tt.id)
		if err != nil {
			t.Errorf("test %d: failed to encode forkid: %v", i, err)
			continue
		}
		if !bytes.Equal(have, tt.want) {
			t.Errorf("test %d: RLP mismatch: have %x, want %x", i, have, tt.want)
		}
	}
}
