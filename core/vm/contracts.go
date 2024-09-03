// Copyright 2014 The Elastos.ELA.SideChain.ESC Authors
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

package vm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/accounts/abi"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common/math"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto/blake2b"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto/bls12381"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto/bn256"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/pledgeBill"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"

	"github.com/elastos/Elastos.ELA/core/contract"
	"github.com/elastos/Elastos.ELA/core/contract/program"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	elaCrypto "github.com/elastos/Elastos.ELA/crypto"
	"golang.org/x/crypto/ripemd160"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64  // RequiredPrice calculates the contract gas use
	Run(input []byte) ([]byte, error) // Run runs the precompiled contract
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):                           &ecrecover{},
	common.BytesToAddress([]byte{2}):                           &sha256hash{},
	common.BytesToAddress([]byte{3}):                           &ripemd160hash{},
	common.BytesToAddress([]byte{4}):                           &dataCopy{},
	common.BytesToAddress([]byte{5}):                           &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}):                           &bn256AddByzantium{},
	common.BytesToAddress([]byte{7}):                           &bn256ScalarMulByzantium{},
	common.BytesToAddress([]byte{8}):                           &bn256PairingByzantium{},
	common.BytesToAddress(params.ArbiterAddress.Bytes()):       &arbiters{},
	common.BytesToAddress(params.P256VerifyAddress.Bytes()):    &p256Verify{},
	common.BytesToAddress(params.SignatureVerifyByPbk.Bytes()): &pbkVerifySignature{},
	common.BytesToAddress(params.PledgeBillVerify.Bytes()):     &pledgeBillVerify{},
	common.BytesToAddress(params.PledgeBillTokenID.Bytes()):    &pledgeBillTokenID{},
}

// PrecompiledContractsIstanbul contains the default set of pre-compiled Ethereum
// contracts used in the Istanbul release.
var PrecompiledContractsIstanbul = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):                             &ecrecover{},
	common.BytesToAddress([]byte{2}):                             &sha256hash{},
	common.BytesToAddress([]byte{3}):                             &ripemd160hash{},
	common.BytesToAddress([]byte{4}):                             &dataCopy{},
	common.BytesToAddress([]byte{5}):                             &bigModExp{},
	common.BytesToAddress([]byte{6}):                             &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):                             &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):                             &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):                             &blake2F{},
	common.BytesToAddress(params.ArbiterAddress.Bytes()):         &arbiters{},
	common.BytesToAddress(params.P256VerifyAddress.Bytes()):      &p256Verify{},
	common.BytesToAddress(params.SignatureVerifyByPbk.Bytes()):   &pbkVerifySignature{},
	common.BytesToAddress(params.PledgeBillVerify.Bytes()):       &pledgeBillVerify{},
	common.BytesToAddress(params.PledgeBillTokenID.Bytes()):      &pledgeBillTokenID{},
	common.BytesToAddress(params.PledgeBillTokenDetail.Bytes()):  &pledgeBillTokenDetail{},
	common.BytesToAddress(params.PledgeBillTokenVersion.Bytes()): &pledgeBillPayloadVersion{},
}

// PrecompiledContractsBLS contains the set of pre-compiled Ethereum
// contracts specified in EIP-2537. These are exported for testing purposes.
var PrecompiledContractsBLS = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{10}):                            &bls12381G1Add{},
	common.BytesToAddress([]byte{11}):                            &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}):                            &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}):                            &bls12381G2Add{},
	common.BytesToAddress([]byte{14}):                            &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}):                            &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}):                            &bls12381Pairing{},
	common.BytesToAddress([]byte{17}):                            &bls12381MapG1{},
	common.BytesToAddress([]byte{18}):                            &bls12381MapG2{},
	common.BytesToAddress(params.ArbiterAddress.Bytes()):         &arbiters{},
	common.BytesToAddress(params.P256VerifyAddress.Bytes()):      &p256Verify{},
	common.BytesToAddress(params.SignatureVerifyByPbk.Bytes()):   &pbkVerifySignature{},
	common.BytesToAddress(params.PledgeBillVerify.Bytes()):       &pledgeBillVerify{},
	common.BytesToAddress(params.PledgeBillTokenID.Bytes()):      &pledgeBillTokenID{},
	common.BytesToAddress(params.PledgeBillTokenDetail.Bytes()):  &pledgeBillTokenDetail{},
	common.BytesToAddress(params.PledgeBillTokenVersion.Bytes()): &pledgeBillPayloadVersion{},
}

// PrecompiledContractsBerlin contains the default set of pre-compiled Ethereum
// contracts used in the Berlin release.
var PrecompiledContractsBerlin = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):                           &ecrecover{},
	common.BytesToAddress([]byte{2}):                           &sha256hash{},
	common.BytesToAddress([]byte{3}):                           &ripemd160hash{},
	common.BytesToAddress([]byte{4}):                           &dataCopy{},
	common.BytesToAddress([]byte{5}):                           &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):                           &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):                           &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):                           &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):                           &blake2F{},
	common.BytesToAddress(params.ArbiterAddress.Bytes()):       &arbiters{},
	common.BytesToAddress(params.P256VerifyAddress.Bytes()):    &p256Verify{},
	common.BytesToAddress(params.SignatureVerifyByPbk.Bytes()): &pbkVerifySignature{},
	common.BytesToAddress(params.PledgeBillVerify.Bytes()):     &pledgeBillVerify{},
	common.BytesToAddress(params.PledgeBillTokenID.Bytes()):    &pledgeBillTokenID{},
	//before release_v0.2.4.2 is not support this contract
	// common.BytesToAddress(params.PledgeBillTokenDetail.Bytes()):  &pledgeBillTokenDetail{},
	// common.BytesToAddress(params.PledgeBillTokenVersion.Bytes()): &pledgeBillPayloadVersion{},
}

var PrecompiledContractsShangHai = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):                             &ecrecover{},
	common.BytesToAddress([]byte{2}):                             &sha256hash{},
	common.BytesToAddress([]byte{3}):                             &ripemd160hash{},
	common.BytesToAddress([]byte{4}):                             &dataCopy{},
	common.BytesToAddress([]byte{5}):                             &bigModExp{eip2565: true},
	common.BytesToAddress([]byte{6}):                             &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):                             &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):                             &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):                             &blake2F{},
	common.BytesToAddress(params.ArbiterAddress.Bytes()):         &arbiters{},
	common.BytesToAddress(params.P256VerifyAddress.Bytes()):      &p256Verify{},
	common.BytesToAddress(params.SignatureVerifyByPbk.Bytes()):   &pbkVerifySignature{},
	common.BytesToAddress(params.PledgeBillVerify.Bytes()):       &pledgeBillVerify{},
	common.BytesToAddress(params.PledgeBillTokenID.Bytes()):      &pledgeBillTokenID{},
	common.BytesToAddress(params.PledgeBillTokenDetail.Bytes()):  &pledgeBillTokenDetail{},
	common.BytesToAddress(params.PledgeBillTokenVersion.Bytes()): &pledgeBillPayloadVersion{},
}

var (
	PrecompiledAddressesShangHai  []common.Address
	PrecompiledAddressesBerlin    []common.Address
	PrecompiledAddressesIstanbul  []common.Address
	PrecompiledAddressesByzantium []common.Address
	PrecompiledAddressesHomestead []common.Address
)

func init() {
	for k := range PrecompiledContractsHomestead {
		PrecompiledAddressesHomestead = append(PrecompiledAddressesHomestead, k)
	}
	for k := range PrecompiledContractsByzantium {
		PrecompiledAddressesByzantium = append(PrecompiledAddressesByzantium, k)
	}
	for k := range PrecompiledContractsIstanbul {
		PrecompiledAddressesIstanbul = append(PrecompiledAddressesIstanbul, k)
	}
	for k := range PrecompiledContractsBerlin {
		PrecompiledAddressesBerlin = append(PrecompiledAddressesBerlin, k)
	}
	for k := range PrecompiledContractsShangHai {
		PrecompiledAddressesShangHai = append(PrecompiledAddressesShangHai, k)
	}
}

// ActivePrecompiles returns the precompiles enabled with the current configuration.
func ActivePrecompiles(rules params.Rules) []common.Address {
	switch {
	case rules.IsShanghai:
		return PrecompiledAddressesShangHai
	case rules.IsBerlin:
		return PrecompiledAddressesBerlin
	case rules.IsIstanbul:
		return PrecompiledAddressesIstanbul
	case rules.IsByzantium:
		return PrecompiledAddressesByzantium
	default:
		return PrecompiledAddressesHomestead
	}
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
func RunPrecompiledContract(p PrecompiledContract, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost
	output, err := p.Run(input)
	return output, suppliedGas, err
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// We must make sure not to modify the 'input', so placing the 'v' along with
	// the signature needs to be done on a new allocation
	sig := make([]byte, 65)
	copy(sig, input[64:128])
	sig[64] = v
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], sig)
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
}
func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
}
func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	ripemd := ripemd160.New()
	ripemd.Write(input)
	return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
}
func (c *dataCopy) Run(in []byte) ([]byte, error) {
	return in, nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct {
	eip2565 bool
}

var (
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	big3      = big.NewInt(3)
	big4      = big.NewInt(4)
	big7      = big.NewInt(7)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big20     = big.NewInt(20)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198
//
// def mult_complexity(x):
//
//	if x <= 64: return x ** 2
//	elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//	else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
func modexpMultComplexity(x *big.Int) *big.Int {
	switch {
	case x.Cmp(big64) <= 0:
		x.Mul(x, x) // x ** 2
	case x.Cmp(big1024) <= 0:
		// (x ** 2 // 4 ) + ( 96 * x - 3072)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, x), big3072),
		)
	default:
		// (x ** 2 // 16) + (480 * x - 199680)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, x), big199680),
		)
	}
	return x
}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))
	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	if c.eip2565 {
		// EIP-2565 has three changes
		// 1. Different multComplexity (inlined here)
		// in EIP-2565 (https://eips.ethereum.org/EIPS/eip-2565):
		//
		// def mult_complexity(x):
		//    ceiling(x/8)^2
		//
		//where is x is max(length_of_MODULUS, length_of_BASE)
		gas = gas.Add(gas, big7)
		gas = gas.Div(gas, big8)
		gas.Mul(gas, gas)

		gas.Mul(gas, math.BigMax(adjExpLen, big1))
		// 2. Different divisor (`GQUADDIVISOR`) (3)
		gas.Div(gas, big3)
		if gas.BitLen() > 64 {
			return math.MaxUint64
		}
		// 3. Minimum price of 200 gas
		if gas.Uint64() < 200 {
			return 200
		}
		return gas.Uint64()
	}
	gas = modexpMultComplexity(gas)
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, big20)

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// runBn256Add implements the Bn256Add precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Add(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256Add implements a native elliptic curve point addition conforming to
// Istanbul consensus rules.
type bn256AddIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasIstanbul
}

func (c *bn256AddIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// bn256AddByzantium implements a native elliptic curve point addition
// conforming to Byzantium consensus rules.
type bn256AddByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasByzantium
}

func (c *bn256AddByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// runBn256ScalarMul implements the Bn256ScalarMul precompile, referenced by
// both Byzantium and Istanbul operations.
func runBn256ScalarMul(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

// bn256ScalarMulIstanbul implements a native elliptic curve scalar
// multiplication conforming to Istanbul consensus rules.
type bn256ScalarMulIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasIstanbul
}

func (c *bn256ScalarMulIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256ScalarMulByzantium implements a native elliptic curve scalar
// multiplication conforming to Byzantium consensus rules.
type bn256ScalarMulByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasByzantium
}

func (c *bn256ScalarMulByzantium) Run(input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// runBn256Pairing implements the Bn256Pairing precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Pairing(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// bn256PairingIstanbul implements a pairing pre-compile for the bn256 curve
// conforming to Istanbul consensus rules.
type bn256PairingIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasIstanbul + uint64(len(input)/192)*params.Bn256PairingPerPointGasIstanbul
}

func (c *bn256PairingIstanbul) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

// bn256PairingByzantium implements a pairing pre-compile for the bn256 curve
// conforming to Byzantium consensus rules.
type bn256PairingByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasByzantium + uint64(len(input)/192)*params.Bn256PairingPerPointGasByzantium
}

func (c *bn256PairingByzantium) Run(input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

type blake2F struct{}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// If the input is malformed, we can't calculate the gas, return 0 and let the
	// actual call choke and fault.
	if len(input) != blake2FInputLength {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

const (
	blake2FInputLength        = 213
	blake2FFinalBlockBytes    = byte(1)
	blake2FNonFinalBlockBytes = byte(0)
)

var (
	errBlake2FInvalidInputLength = errors.New("invalid input length")
	errBlake2FInvalidFinalFlag   = errors.New("invalid final flag")
)

func (c *blake2F) Run(input []byte) ([]byte, error) {
	// Make sure the input is valid (correct lenth and final flag)
	if len(input) != blake2FInputLength {
		return nil, errBlake2FInvalidInputLength
	}
	if input[212] != blake2FNonFinalBlockBytes && input[212] != blake2FFinalBlockBytes {
		return nil, errBlake2FInvalidFinalFlag
	}
	// Parse the input into the Blake2b call parameters
	var (
		rounds = binary.BigEndian.Uint32(input[0:4])
		final  = (input[212] == blake2FFinalBlockBytes)

		h [8]uint64
		m [16]uint64
		t [2]uint64
	)
	for i := 0; i < 8; i++ {
		offset := 4 + i*8
		h[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	for i := 0; i < 16; i++ {
		offset := 68 + i*8
		m[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	t[0] = binary.LittleEndian.Uint64(input[196:204])
	t[1] = binary.LittleEndian.Uint64(input[204:212])

	// Execute the compression function, extract and return the result
	blake2b.F(&h, m, t, final, rounds)

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		offset := i * 8
		binary.LittleEndian.PutUint64(output[offset:offset+8], h[i])
	}
	return output, nil
}

var (
	errGettingArbitersFailed = errors.New("getting arbiters failed")
)

type arbiters struct{}

func (c *arbiters) RequiredGas(input []byte) uint64 {
	return params.ArbitersBaseGas
}

func (c *arbiters) Run(input []byte) ([]byte, error) {
	arbiters, _, err := spv.GetArbiters()
	if err != nil {
		return nil, errGettingArbitersFailed
	}
	ret := make([]byte, 0)
	for _, pubkey := range arbiters {
		hash := crypto.Keccak256(common.Hex2Bytes(pubkey))
		ret = append(ret, common.LeftPadBytes(hash[:], 32)...)
	}

	return ret, nil
}

const (
	p256VerifyInputLength = 193
)

var (
	errP256VerifyInvalidInputLength = errors.New("invalid input length")
	errP256VerifyInvalidPublicKey   = errors.New("invalid public key")
)

type p256Verify struct{}

func (c *p256Verify) RequiredGas(input []byte) uint64 {
	return params.P256VerifyBaseGas
}

func (c *p256Verify) Run(input []byte) ([]byte, error) {
	// Make sure the input is valid (correct length)
	if len(input) != p256VerifyInputLength {
		return nil, errP256VerifyInvalidInputLength
	}
	//length := getData(input, 0, 32)
	pubkey := getData(input, 32, 33)
	data := getData(input, 65, 64)
	sig := getData(input, 129, 64)
	publicKey, err := elaCrypto.DecodePoint(pubkey)
	if err != nil {
		return nil, errP256VerifyInvalidPublicKey
	}
	err = elaCrypto.Verify(*publicKey, data, sig)
	if err != nil {
		return false32Byte, nil
	}
	return true32Byte, nil
}

type pbkVerifySignature struct{}

func (b *pbkVerifySignature) RequiredGas(input []byte) uint64 {
	return params.PbkVerifySignature
}

func (b *pbkVerifySignature) Run(input []byte) ([]byte, error) {
	//length := getData(input, 0, 32)
	pubkey := getData(input, 32, 33)
	digest := getData(input, 65, 32)
	sig := getData(input, 97, 65)
	digest = accounts.TextHash(digest)

	if sig[crypto.RecoveryIDOffset] >= 27 {
		sig[crypto.RecoveryIDOffset] -= 27
	}
	signerPuk, err := crypto.SigToPub(digest, sig)
	if err != nil {
		fmt.Println("SigToPub error", signerPuk, err)
		return false32Byte, err
	}
	pubkeyBytes := crypto.CompressPubkey(signerPuk)

	if bytes.Equal(pubkeyBytes, pubkey) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

type pledgeBillVerify struct{}

func (b *pledgeBillVerify) RequiredGas(input []byte) uint64 {
	return params.PledgeBillVerifyGas
}

func (b *pledgeBillVerify) Run(input []byte) ([]byte, error) {
	elaHash := getData(input, 32, 32)
	toAddress := getData(input, 64, 20)
	toAddress = toAddress[:common.AddressLength]
	multiN := getData(input, 84, 32)
	multiM := getData(input, 116, 32)
	sigLen := getData(input, 148, 32)
	var startPoint int64 = 180
	var i int64
	n := big.NewInt(0).SetBytes(multiN)
	m := big.NewInt(0).SetBytes(multiM)
	publickeys := make([]*elaCrypto.PublicKey, 0)
	var point uint64
	for i = 0; i < n.Int64(); i++ {
		point = uint64(startPoint + (i * 33))
		pub := getData(input, point, 33)
		pbk, err := elaCrypto.DecodePoint(pub)
		if err != nil {
			return false32Byte, errors.New("publicKey decode error")
		}
		publickeys = append(publickeys, pbk)

	}
	point = point + 33
	signatures := make([]byte, 0)

	if n.Int64() == 1 {
		signature := getData(input, point, 64)
		err := checkStandardSignature(publickeys[0], elaHash, toAddress, signature)
		if err != nil {
			log.Error("checkStandardSignature failed", "err", err)
			return false32Byte, err
		}
	} else if m.Uint64() > 1 && n.Uint64() > 1 {
		sigCount := big.NewInt(0).SetBytes(sigLen)
		for i = 0; i < sigCount.Int64(); i++ {
			c := point + (uint64(i) * 64)
			signature := getData(input, c, 64)
			signatures = append(signatures, getParameterBySignature(signature)...)
		}
		if n.Cmp(m) < 0 {
			return false32Byte, errors.New("n is smaller than m")
		}
		err := checkMultiSignatures(int(m.Int64()), publickeys, signatures, elaHash, toAddress)
		if err != nil {
			log.Error("checkMultiSignatures failed", "err", err)
			return false32Byte, err
		}
	} else {
		return false32Byte, errors.New("error signature params")
	}
	return true32Byte, nil
}

func getParameterBySignature(signature []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(len(signature)))
	buf.Write(signature)
	return buf.Bytes()
}

func checkStandardSignature(pubKey *elaCrypto.PublicKey, elaHash []byte, toAddress []byte, signature []byte) error {
	data := append(elaHash, toAddress...)
	err := elaCrypto.Verify(*pubKey, data, signature)
	if err != nil {
		return err
	}
	redeemScript, err := contract.CreateStandardRedeemScript(pubKey)
	if err != nil {
		return err
	}
	ct, err := contract.CreateStakeContractByCode(redeemScript[:])
	if err != nil {
		return err
	}
	stakeAddress, err := ct.ToProgramHash().ToAddress()

	sAddress, _, err := pledgeBill.GetPledgeBillData(common.BytesToHash(elaHash).String())
	if err != nil {
		log.Info("general stakeAddress", "", stakeAddress)
		return err
	}
	if sAddress != stakeAddress {
		return errors.New(fmt.Sprintf("stakeAddress is not correct, spv sAddress%s, callSaddress:%s", sAddress, stakeAddress))
	}
	return nil
}

func checkMultiSignatures(m int, publickeys []*elaCrypto.PublicKey, signatures []byte, elaHash []byte, toAddress []byte) error {
	ct, err := contract.CreateMultiSigContract(m, publickeys)
	if err != nil {
		return err
	}
	pro := program.Program{
		Code:      ct.Code,
		Parameter: signatures,
	}
	data := append(elaHash, toAddress...)
	err = elaCrypto.CheckMultiSigSignatures(pro, data)
	if err != nil {
		return err
	}
	ct.Prefix = contract.PrefixDPoSV2
	stakeAddress, err := ct.ToProgramHash().ToAddress()
	if err != nil {
		return err
	}
	sAddress, _, err := pledgeBill.GetPledgeBillData(common.BytesToHash(elaHash).String())
	if sAddress != stakeAddress {
		return errors.New(fmt.Sprintf("stakeAddress is not correct, spv sAddress%s, callSaddress:%s", sAddress, stakeAddress))
	}
	return nil
}

type pledgeBillTokenID struct{}

func (b *pledgeBillTokenID) RequiredGas(input []byte) uint64 {
	return params.GetPledgeBillTokenID
}

func (b *pledgeBillTokenID) Run(input []byte) ([]byte, error) {
	//length := getData(input, 0, 32)
	elaHash := getData(input, 32, 32)

	_, tokenID, err := pledgeBill.GetPledgeBillData(common.BytesToHash(elaHash).String())
	if err != nil {
		log.Info("pledgeBillTokenID", "elaHash", elaHash, "hash", common.BytesToHash(elaHash).String(), "tokenID", tokenID)
		return false32Byte, err
	}
	return tokenID.Bytes(), nil
}

type pledgeBillTokenDetail struct{}

func (p *pledgeBillTokenDetail) RequiredGas(input []byte) uint64 {
	return params.GetPledgeBillTokenDetail
}

func (p *pledgeBillTokenDetail) Run(input []byte) ([]byte, error) {
	//length := getData(input, 0, 32)
	elaHash := getData(input, 32, 32)
	nftPayload, payloadVersion, err := pledgeBill.GetCreateNFTPayload(common.BytesToHash(elaHash).String())
	if err != nil {
		log.Info("pledgeBillTokenDetail", "elaHash", elaHash, "hash", common.BytesToHash(elaHash).String())
		return false32Byte, err
	}

	if payloadVersion == payload.CreateNFTVersion {
		nftPayload.StartHeight = 0
		nftPayload.EndHeight = 0
		nftPayload.Votes = 0
		nftPayload.VoteRights = 0
		nftPayload.TargetOwnerKey = []byte{}
	}
	arguments := make([]abi.Argument, 0)
	Bytes32, _ := abi.NewType("bytes32", "bytes32", nil)
	UInt32, _ := abi.NewType("uint32", "uint32", nil)
	Int64, _ := abi.NewType("int64", "int64", nil)
	String, _ := abi.NewType("string", "string", nil)
	Bytes, _ := abi.NewType("bytes", "bytes", nil)

	Referkey := abi.Argument{Name: "referKey", Type: Bytes32}
	arguments = append(arguments, Referkey)

	StakeAddress := abi.Argument{Name: "stakeAddress", Type: String}
	arguments = append(arguments, StakeAddress)

	GenesisBlockHash := abi.Argument{Name: "genesisBlockHash", Type: Bytes32}
	arguments = append(arguments, GenesisBlockHash)

	StartHeight := abi.Argument{Name: "startHeight", Type: UInt32}
	arguments = append(arguments, StartHeight)

	EndHeight := abi.Argument{Name: "endHeight", Type: UInt32}
	arguments = append(arguments, EndHeight)

	Votes := abi.Argument{Name: "votes", Type: Int64}
	arguments = append(arguments, Votes)

	VotesRight := abi.Argument{Name: "votesRight", Type: Int64}
	arguments = append(arguments, VotesRight)

	Owner := abi.Argument{Name: "targetOwner", Type: Bytes}
	arguments = append(arguments, Owner)

	m := abi.Method{Inputs: arguments}
	ret, err := m.Inputs.Pack(nftPayload.ReferKey, nftPayload.StakeAddress, nftPayload.GenesisBlockHash, nftPayload.StartHeight, nftPayload.EndHeight, nftPayload.Votes, nftPayload.VoteRights, nftPayload.TargetOwnerKey[:])
	if err != nil {
		log.Error("pledgeBillTokenDetail ailed ", "error ", err)
		return ret, err
	}
	return ret, nil
}

type pledgeBillPayloadVersion struct{}

func (p *pledgeBillPayloadVersion) RequiredGas(input []byte) uint64 {
	return params.GetPledgeBillTokenID
}

func (p *pledgeBillPayloadVersion) Run(input []byte) ([]byte, error) {
	elaHash := getData(input, 32, 32)
	v, err := pledgeBill.GetBPosNftPayloadVersion(common.BytesToHash(elaHash).String())
	version := big.NewInt(int64(v))
	if err != nil {
		log.Warn("GetBPosNftPayloadVerson failed", "error", err)
	}
	return common.LeftPadBytes(version.Bytes(), 32), err
}

var (
	errBLS12381InvalidInputLength          = errors.New("invalid input length")
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
	errBLS12381G1PointSubgroup             = errors.New("g1 point is not on correct subgroup")
	errBLS12381G2PointSubgroup             = errors.New("g2 point is not on correct subgroup")
)

// bls12381G1Add implements EIP-2537 G1Add precompile.
type bls12381G1Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1AddGas
}

func (c *bls12381G1Add) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Add precompile.
	// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	if len(input) != 256 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point p_0
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode G1 point p_1
	if p1, err = g.DecodePoint(input[128:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	r := g.New()
	g.Add(r, p0, p1)

	// Encode the G1 point result into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1Mul implements EIP-2537 G1Mul precompile.
type bls12381G1Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1MulGas
}

func (c *bls12381G1Mul) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Mul precompile.
	// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	if len(input) != 160 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[128:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G1 point into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1MultiExp implements EIP-2537 G1MultiExp precompile.
type bls12381G1MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G1 point, scalar value pair length
	k := len(input) / 160
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G1 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G1MulGas * discount) / 1000
}

func (c *bls12381G1MultiExp) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G1MultiExp precompile.
	// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG1, k)
	scalars := make([]*big.Int, k)

	// Initialize G1
	g := bls12381.NewG1()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 160 * i
		t0, t1, t2 := off, off+128, off+160
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Add implements EIP-2537 G2Add precompile.
type bls12381G2Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2AddGas
}

func (c *bls12381G2Add) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2Add precompile.
	// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	if len(input) != 512 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()
	r := g.New()

	// Decode G2 point p_0
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode G2 point p_1
	if p1, err = g.DecodePoint(input[256:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	g.Add(r, p0, p1)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Mul implements EIP-2537 G2Mul precompile.
type bls12381G2Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2MulGas
}

func (c *bls12381G2Mul) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MUL precompile logic.
	// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	if len(input) != 288 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()

	// Decode G2 point
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[256:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2MultiExp implements EIP-2537 G2MultiExp precompile.
type bls12381G2MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G2 point, scalar value pair length
	k := len(input) / 288
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G2 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G2MulGas * discount) / 1000
}

func (c *bls12381G2MultiExp) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MultiExp precompile logic
	// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	k := len(input) / 288
	if len(input) == 0 || len(input)%288 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG2, k)
	scalars := make([]*big.Int, k)

	// Initialize G2
	g := bls12381.NewG2()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 288 * i
		t0, t1, t2 := off, off+256, off+288
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G2 point to 256 bytes.
	return g.EncodePoint(r), nil
}

// bls12381Pairing implements EIP-2537 Pairing precompile.
type bls12381Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381Pairing) RequiredGas(input []byte) uint64 {
	return params.Bls12381PairingBaseGas + uint64(len(input)/384)*params.Bls12381PairingPerPairGas
}

func (c *bls12381Pairing) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	// Initialize BLS12-381 pairing engine
	e := bls12381.NewPairingEngine()
	g1, g2 := e.G1, e.G2

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := g1.DecodePoint(input[t0:t1])
		if err != nil {
			return nil, err
		}
		// Decode G2 point
		p2, err := g2.DecodePoint(input[t1:t2])
		if err != nil {
			return nil, err
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !g1.InCorrectSubgroup(p1) {
			return nil, errBLS12381G1PointSubgroup
		}
		if !g2.InCorrectSubgroup(p2) {
			return nil, errBLS12381G2PointSubgroup
		}

		// Update pairing engine with G1 and G2 ponits
		e.AddPair(p1, p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	if e.Check() {
		out[31] = 1
	}
	return out, nil
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return nil, errBLS12381InvalidFieldElementTopBytes
		}
	}
	out := make([]byte, 48)
	copy(out[:], in[16:])
	return out, nil
}

// bls12381MapG1 implements EIP-2537 MapG1 precompile.
type bls12381MapG1 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG1) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG1Gas
}

func (c *bls12381MapG1) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_To_G1 precompile.
	// > Field-to-curve call expects `64` bytes an an input that is interpreted as a an element of the base field.
	// > Output of this call is `128` bytes and is G1 point following respective encoding rules.
	if len(input) != 64 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe, err := decodeBLS12381FieldElement(input)
	if err != nil {
		return nil, err
	}

	// Initialize G1
	g := bls12381.NewG1()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381MapG2 implements EIP-2537 MapG2 precompile.
type bls12381MapG2 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG2) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG2Gas
}

func (c *bls12381MapG2) Run(input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_FP2_TO_G2 precompile logic.
	// > Field-to-curve call expects `128` bytes an an input that is interpreted as a an element of the quadratic extension field.
	// > Output of this call is `256` bytes and is G2 point following respective encoding rules.
	if len(input) != 128 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe := make([]byte, 96)
	c0, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		return nil, err
	}
	copy(fe[48:], c0)
	c1, err := decodeBLS12381FieldElement(input[64:])
	if err != nil {
		return nil, err
	}
	copy(fe[:48], c1)

	// Initialize G2
	g := bls12381.NewG2()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G2 point to 256 bytes
	return g.EncodePoint(r), nil
}
