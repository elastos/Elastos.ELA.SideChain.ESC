// Copyright (c) 2018 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package psbt is an implementation of Partially Signed Bitcoin
// Transactions (PSBT). The format is defined in BIP 174:
// https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
package psbt

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"io"
	"sort"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// BIP-174 aka PSBT defined values

// Key types are currently encoded with single bytes
type psbtKeyType = uint8

const psbtMagicLength = 5

var (
	psbtMagic = [psbtMagicLength]byte{0x70,
		0x73, 0x62, 0x74, 0xff, // = "psbt" + 0xff sep
	}
)

// MaxPsbtValueLength is the size of the largest transaction serialization
// that could be passed in a NonWitnessUtxo field. This is definitely
//less than 4M.
const MaxPsbtValueLength = 4000000

// The below are the known key types as per the BIP.
// Unknown types may be accepted but will not be processed.
const (

	// Global known key types
	PsbtGlobalUnsignedTx psbtKeyType = 0

	// TxIn section known key types
	PsbtInNonWitnessUtxo     psbtKeyType = 0
	PsbtInWitnessUtxo        psbtKeyType = 1
	PsbtInPartialSig         psbtKeyType = 2
	PsbtInSighashType        psbtKeyType = 3
	PsbtInRedeemScript       psbtKeyType = 4
	PsbtInWitnessScript      psbtKeyType = 5
	PsbtInBip32Derivation    psbtKeyType = 6
	PsbtInFinalScriptSig     psbtKeyType = 7
	PsbtInFinalScriptWitness psbtKeyType = 8

	// TxOut section known key types
	PsbtOutRedeemScript    psbtKeyType = 0
	PsbtOutWitnessScript   psbtKeyType = 1
	PsbtOutBip32Derivation psbtKeyType = 2
)

var (

	// ErrInvalidPsbtFormat is a generic error for any situation in which a
	// provided Psbt serialization does not conform to the rules of BIP174.
	ErrInvalidPsbtFormat = errors.New("Invalid PSBT serialization format")

	// ErrDuplicateKey indicates that a passed Psbt serialization is invalid
	// due to having the same key repeated in the same key-value pair.
	ErrDuplicateKey = errors.New("Invalid Psbt due to duplicate key")

	// ErrInvalidKeydata indicates that a key-value pair in the PSBT
	// serialization contains data in the key which is not valid.
	ErrInvalidKeydata = errors.New("Invalid key data")

	// ErrInvalidMagicBytes indicates that a passed Psbt serialization is invalid
	// due to having incorrect magic bytes.
	ErrInvalidMagicBytes = errors.New("Invalid Psbt due to incorrect magic bytes")

	// ErrInvalidRawTxSigned indicates that the raw serialized transaction in the
	// global section of the passed Psbt serialization is invalid because it
	// contains scriptSigs/witnesses (i.e. is fully or partially signed), which
	// is not allowed by BIP174.
	ErrInvalidRawTxSigned = errors.New("Invalid Psbt, raw transaction must " +
		"be unsigned.")

	// ErrInvalidPrevOutNonWitnessTransaction indicates that the transaction
	// hash (i.e. SHA256^2) of the fully serialized previous transaction
	// provided in the NonWitnessUtxo key-value field doesn't match the prevout
	// hash in the UnsignedTx field in the PSBT itself.
	ErrInvalidPrevOutNonWitnessTransaction = errors.New("Prevout hash does " +
		"not match the provided non-witness utxo serialization")

	// ErrInvalidSignatureForInput indicates that the signature the user is
	// trying to append to the PSBT is invalid, either because it does
	// not correspond to the previous transaction hash, or redeem script,
	// or witness script.
	// NOTE this does not include ECDSA signature checking.
	ErrInvalidSignatureForInput = errors.New("Signature does not correspond " +
		"to this input")

	// ErrInputAlreadyFinalized indicates that the PSBT passed to a Finalizer
	// already contains the finalized scriptSig or witness.
	ErrInputAlreadyFinalized = errors.New("Cannot finalize PSBT, finalized " +
		"scriptSig or scriptWitnes already exists")

	// ErrIncompletePSBT indicates that the Extractor object
	// was unable to successfully extract the passed Psbt struct because
	// it is not complete
	ErrIncompletePSBT = errors.New("PSBT cannot be extracted as it is " +
		"incomplete")

	// ErrNotFinalizable indicates that the PSBT struct does not have
	// sufficient data (e.g. signatures) for finalization
	ErrNotFinalizable = errors.New("PSBT is not finalizable")

	// ErrInvalidSigHashFlags indicates that a signature added to the PSBT
	// uses Sighash flags that are not in accordance with the requirement
	// according to the entry in PsbtInSighashType, or otherwise not the
	// default value (SIGHASH_ALL)
	ErrInvalidSigHashFlags = errors.New("Invalid Sighash Flags")

	// ErrUnsupportedScriptType indicates that the redeem script or
	// scriptwitness given is not supported by this codebase, or is otherwise
	// not valid.
	ErrUnsupportedScriptType = errors.New("Unsupported script type")
)

func serializeKVpair(w io.Writer, key []byte, value []byte) error {
	err := wire.WriteVarBytes(w, 0, key)
	if err != nil {
		return err
	}
	err = wire.WriteVarBytes(w, 0, value)
	if err != nil {
		return err
	}
	return nil
}

func serializeKVPairWithType(w io.Writer, kt psbtKeyType, keydata []byte,
	value []byte) error {
	if keydata == nil {
		keydata = []byte{}
	}
	serializedKey := append([]byte{byte(kt)}, keydata...)
	return serializeKVpair(w, serializedKey, value)
}

// getKey retrieves a single key - both the key type and the keydata
// (if present) from the stream and returns the key type as an integer,
// or -1 if the key was of zero length, which is used to indicate the
// presence of a separator byte which indicates the end of a given key-
// value pair list, and the keydata as a byte slice or nil if none is
// present.
func getKey(r io.Reader) (int, []byte, error) {

	// For the key, we read the varint separately, instead of
	// using the available ReadVarBytes, because we have a specific
	// treatment of 0x00 here:
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return -1, nil, ErrInvalidPsbtFormat
	}
	if count == 0 {
		// separator indicates end of key-value pair list
		return -1, nil, nil
	}

	// read count bytes, this is the key (including type and any data)
	var keyintanddata = make([]byte, count)
	if _, err := io.ReadFull(r, keyintanddata[:]); err != nil {
		return -1, nil, err
	}

	keyType := int(string(keyintanddata)[0])
	// Note that the second return value will usually be empty,
	// since most keys contain no more than the key type byte.
	if len(keyintanddata) == 1 {
		return keyType, nil, nil
	}
	return keyType, keyintanddata[1:], nil

}

// readTxOut is a limited version of wire.readTxOut, because
// the latter is not exported.
func readTxOut(txout []byte) (*wire.TxOut, error) {
	if len(txout) < 10 {
		return nil, ErrInvalidPsbtFormat
	}
	valueSer := binary.LittleEndian.Uint64(txout[:8])
	scriptPubKey := txout[9:]
	return wire.NewTxOut(int64(valueSer), scriptPubKey), nil
}

// PartialSig encapsulate a (BTC public key, ECDSA signature)
// pair, note that the fields are stored as byte slices, not
// btcec.PublicKey or btcec.Signature (because manipulations will
// be with the former not the latter, here); compliance with consensus
// serialization is enforced with .checkValid()
type PartialSig struct {
	PubKey    []byte
	Signature []byte
}

// PartialSigSorter implements sort.Interface.
type PartialSigSorter []*PartialSig

func (s PartialSigSorter) Len() int { return len(s) }

func (s PartialSigSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s PartialSigSorter) Less(i, j int) bool {
	return bytes.Compare(s[i].PubKey, s[j].PubKey) < 0
}

// validatePubkey checks if pubKey is *any* valid
// pubKey serialization in a Bitcoin context (compressed/uncomp. OK)
func validatePubkey(pubKey []byte) bool {
	_, err := btcec.ParsePubKey(pubKey, btcec.S256())
	if err != nil {
		return false
	}
	return true
}

// validateSignature checks that the passed byte slice is a valid
// DER-encoded ECDSA signature, including the sighash flag.
// It does *not* of course validate the signature against any message
// or public key.
func validateSignature(sig []byte) bool {
	_, err := btcec.ParseDERSignature(sig, btcec.S256())
	if err != nil {
		return false
	}
	return true
}

// See above notes (PartialSig, validatePubkey, validateSignature).
// NOTE update for Schnorr will be needed here if/when that activates.
func (ps *PartialSig) checkValid() bool {
	return validatePubkey(ps.PubKey) && validateSignature(ps.Signature)
}

// Bip32Derivation encapsulates the data for the input and output
// Bip32Derivation key-value fields.
type Bip32Derivation struct {
	PubKey               []byte
	MasterKeyFingerprint uint32
	Bip32Path            []uint32
}

// checkValid ensures that the PubKey in the Bip32Derivation
// struct is valid.
func (pb *Bip32Derivation) checkValid() bool {
	return validatePubkey(pb.PubKey)
}

// Bip32Sorter implements sort.Interface.
type Bip32Sorter []*Bip32Derivation

func (s Bip32Sorter) Len() int { return len(s) }

func (s Bip32Sorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s Bip32Sorter) Less(i, j int) bool {
	return bytes.Compare(s[i].PubKey, s[j].PubKey) < 0
}

// readBip32Derivation deserializes a byte slice containing
// chunks of 4 byte little endian encodings of uint32 values,
// the first of which is the masterkeyfingerprint and the remainder
// of which are the derivation path.
func readBip32Derivation(path []byte) (uint32, []uint32, error) {

	if len(path)%4 != 0 || len(path)/4-1 < 1 {
		return 0, nil, ErrInvalidPsbtFormat
	}
	masterKeyInt := binary.LittleEndian.Uint32(path[:4])
	paths := make([]uint32, 0)
	for i := 4; i < len(path); i += 4 {
		paths = append(paths, binary.LittleEndian.Uint32(path[i:i+4]))
	}
	return masterKeyInt, paths, nil
}

// SerializeBIP32Derivation takes a master key fingerprint
// as defined in BIP32, along with a path specified as a list
// of uint32 values, and returns a bytestring specifying the derivation
// in the format required by BIP174:
// // master key fingerprint (4) || child index (4) || child index (4) || ...
func SerializeBIP32Derivation(masterKeyFingerprint uint32,
	bip32Path []uint32) []byte {
	derivationPath := make([]byte, 0, 4+4*len(bip32Path))
	var masterKeyBytes [4]byte
	binary.LittleEndian.PutUint32(masterKeyBytes[:], masterKeyFingerprint)
	derivationPath = append(derivationPath, masterKeyBytes[:]...)
	for _, path := range bip32Path {
		var pathbytes [4]byte
		binary.LittleEndian.PutUint32(pathbytes[:], path)
		derivationPath = append(derivationPath, pathbytes[:]...)
	}
	return derivationPath
}

// Unknown is a struct encapsulating a key-value pair for which
// the key type is unknown by this package; these fields are allowed
// in both the 'Global' and the 'Input' section of a PSBT.
type Unknown struct {
	Key   []byte
	Value []byte
}

// PInput is a struct encapsulating all the data that can be attached
// to any specific input of the PSBT.
type PInput struct {
	NonWitnessUtxo     *wire.MsgTx
	WitnessUtxo        *wire.TxOut
	PartialSigs        []*PartialSig
	SighashType        txscript.SigHashType
	RedeemScript       []byte
	WitnessScript      []byte
	Bip32Derivation    []*Bip32Derivation
	FinalScriptSig     []byte
	FinalScriptWitness []byte
	Unknowns           []*Unknown
}

// NewPsbtInput creates an instance of PsbtInput given either a
// nonWitnessUtxo or a witnessUtxo.
// NOTE only one of the two arguments should be specified, with the other
// being `nil`; otherwise the created PsbtInput object will fail IsSane()
// checks and will not be usable.
func NewPsbtInput(nonWitnessUtxo *wire.MsgTx,
	witnessUtxo *wire.TxOut) *PInput {
	return &PInput{
		NonWitnessUtxo:     nonWitnessUtxo,
		WitnessUtxo:        witnessUtxo,
		PartialSigs:        []*PartialSig{},
		SighashType:        0,
		RedeemScript:       nil,
		WitnessScript:      nil,
		Bip32Derivation:    []*Bip32Derivation{},
		FinalScriptSig:     nil,
		FinalScriptWitness: nil,
		Unknowns:           nil,
	}
}

// IsSane returns true only if there are no conflicting
// values in the Psbt PInput. It checks that witness and non-witness
// utxo entries do not both exist, and that witnessScript entries are only
// added to witness inputs.
func (pi *PInput) IsSane() bool {

	if pi.NonWitnessUtxo != nil && pi.WitnessUtxo != nil {
		return false
	}
	if pi.WitnessUtxo == nil && pi.WitnessScript != nil {
		return false
	}
	if pi.WitnessUtxo == nil && pi.FinalScriptWitness != nil {
		return false
	}

	return true
}

func (pi *PInput) deserialize(r io.Reader) error {
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return err
		}
		if keyint == -1 {
			// Reached separator byte
			break
		}
		value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
			"PSBT value")
		if err != nil {
			return err
		}

		switch uint8(keyint) {

		case PsbtInNonWitnessUtxo:
			if pi.NonWitnessUtxo != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			tx := wire.NewMsgTx(2)
			if err := tx.Deserialize(bytes.NewReader(value)); err != nil {
				return err
			}
			pi.NonWitnessUtxo = tx

		case PsbtInWitnessUtxo:
			if pi.WitnessUtxo != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			txout, err := readTxOut(value)
			if err != nil {
				return err
			}
			pi.WitnessUtxo = txout

		case PsbtInPartialSig:
			newPartialSig := PartialSig{PubKey: keydata,
				Signature: value}
			if !newPartialSig.checkValid() {
				return ErrInvalidPsbtFormat
			}
			// Duplicate keys are not allowed
			for _, x := range pi.PartialSigs {
				if bytes.Equal(x.PubKey, newPartialSig.PubKey) {
					return ErrDuplicateKey
				}
			}
			pi.PartialSigs = append(pi.PartialSigs, &newPartialSig)

		case PsbtInSighashType:
			if pi.SighashType != 0 {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			shtype := txscript.SigHashType(binary.LittleEndian.Uint32(value))
			pi.SighashType = shtype

		case PsbtInRedeemScript:
			if pi.RedeemScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.RedeemScript = value

		case PsbtInWitnessScript:
			if pi.WitnessScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.WitnessScript = value

		case PsbtInBip32Derivation:
			if !validatePubkey(keydata) {
				return ErrInvalidPsbtFormat
			}
			master, derivationPath, err := readBip32Derivation(value)
			if err != nil {
				return err
			}
			// Duplicate keys are not allowed
			for _, x := range pi.Bip32Derivation {
				if bytes.Equal(x.PubKey, keydata) {
					return ErrDuplicateKey
				}
			}
			pi.Bip32Derivation = append(pi.Bip32Derivation,
				&Bip32Derivation{
					PubKey:               keydata,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				})

		case PsbtInFinalScriptSig:
			if pi.FinalScriptSig != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.FinalScriptSig = value

		case PsbtInFinalScriptWitness:
			if pi.FinalScriptWitness != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			pi.FinalScriptWitness = value

		default:
			keyintanddata := []byte{byte(keyint)}
			keyintanddata = append(keyintanddata, keydata...)
			newUnknown := &Unknown{
				Key:   keyintanddata,
				Value: value,
			}
			// Duplicate key+keydata are not allowed
			for _, x := range pi.Unknowns {
				if bytes.Equal(x.Key, newUnknown.Key) && bytes.Equal(x.Value,
					newUnknown.Value) {
					return ErrDuplicateKey
				}
			}
			pi.Unknowns = append(pi.Unknowns, newUnknown)
		}
	}
	return nil
}

func (pi *PInput) serialize(w io.Writer) error {

	if !pi.IsSane() {
		return ErrInvalidPsbtFormat
	}

	if pi.NonWitnessUtxo != nil {
		var buf bytes.Buffer
		err := pi.NonWitnessUtxo.Serialize(&buf)
		if err != nil {
			return err
		}
		err = serializeKVPairWithType(w, PsbtInNonWitnessUtxo, nil,
			buf.Bytes())
		if err != nil {
			return err
		}
	}
	if pi.WitnessUtxo != nil {

		var buf bytes.Buffer
		err := wire.WriteTxOut(&buf, 0, 0, pi.WitnessUtxo)
		if err != nil {
			return err
		}
		err = serializeKVPairWithType(w, PsbtInWitnessUtxo, nil, buf.Bytes())
		if err != nil {
			return err
		}
	}
	if pi.FinalScriptSig == nil && pi.FinalScriptWitness == nil {

		sort.Sort(PartialSigSorter(pi.PartialSigs))
		for _, ps := range pi.PartialSigs {
			err := serializeKVPairWithType(w, PsbtInPartialSig, ps.PubKey,
				ps.Signature)
			if err != nil {
				return err
			}
		}

		if pi.SighashType != 0 {
			var shtBytes [4]byte
			binary.LittleEndian.PutUint32(shtBytes[:],
				uint32(pi.SighashType))
			err := serializeKVPairWithType(w, PsbtInSighashType, nil,
				shtBytes[:])
			if err != nil {
				return err
			}
		}
		if pi.RedeemScript != nil {
			err := serializeKVPairWithType(w, PsbtInRedeemScript, nil,
				pi.RedeemScript)
			if err != nil {
				return err
			}
		}
		if pi.WitnessScript != nil {
			err := serializeKVPairWithType(w, PsbtInWitnessScript, nil,
				pi.WitnessScript)
			if err != nil {
				return err
			}
		}

		sort.Sort(Bip32Sorter(pi.Bip32Derivation))
		for _, kd := range pi.Bip32Derivation {
			err := serializeKVPairWithType(w, PsbtInBip32Derivation,
				kd.PubKey,
				SerializeBIP32Derivation(kd.MasterKeyFingerprint,
					kd.Bip32Path))
			if err != nil {
				return err
			}
		}
	}

	if pi.FinalScriptSig != nil {
		err := serializeKVPairWithType(w, PsbtInFinalScriptSig, nil,
			pi.FinalScriptSig)
		if err != nil {
			return err
		}
	}

	if pi.FinalScriptWitness != nil {
		err := serializeKVPairWithType(w, PsbtInFinalScriptWitness, nil,
			pi.FinalScriptWitness)
		if err != nil {
			return err
		}
	}

	// Unknown is a special case; we don't have a key type, only
	// a key and a value field
	for _, kv := range pi.Unknowns {
		err := serializeKVpair(w, kv.Key, kv.Value)
		if err != nil {
			return err
		}
	}

	return nil
}

// POutput is a struct encapsulating all the data that can be attached
// to any specific output of the PSBT.
type POutput struct {
	RedeemScript    []byte
	WitnessScript   []byte
	Bip32Derivation []*Bip32Derivation
}

// NewPsbtOutput creates an instance of PsbtOutput; the three parameters
// redeemScript, witnessScript and Bip32Derivation are all allowed to be
// `nil`.
func NewPsbtOutput(redeemScript []byte, witnessScript []byte,
	bip32Derivation []*Bip32Derivation) *POutput {
	return &POutput{
		RedeemScript:    redeemScript,
		WitnessScript:   witnessScript,
		Bip32Derivation: bip32Derivation,
	}
}

func (po *POutput) deserialize(r io.Reader) error {
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return err
		}
		if keyint == -1 {
			// Reached separator byte
			break
		}
		value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
			"PSBT value")
		if err != nil {
			return err
		}

		switch uint8(keyint) {

		case PsbtOutRedeemScript:
			if po.RedeemScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			po.RedeemScript = value

		case PsbtOutWitnessScript:
			if po.WitnessScript != nil {
				return ErrDuplicateKey
			}
			if keydata != nil {
				return ErrInvalidKeydata
			}
			po.WitnessScript = value

		case PsbtOutBip32Derivation:
			if !validatePubkey(keydata) {
				return ErrInvalidKeydata
			}
			master, derivationPath, err := readBip32Derivation(value)
			if err != nil {
				return err
			}
			// Duplicate keys are not allowed
			for _, x := range po.Bip32Derivation {
				if bytes.Equal(x.PubKey, keydata) {
					return ErrDuplicateKey
				}
			}
			po.Bip32Derivation = append(po.Bip32Derivation,
				&Bip32Derivation{
					PubKey:               keydata,
					MasterKeyFingerprint: master,
					Bip32Path:            derivationPath,
				})

		default:
			// unknown type is allowed for inputs but not outputs
			return ErrInvalidPsbtFormat
		}
	}
	return nil
}

func (po *POutput) serialize(w io.Writer) error {
	if po.RedeemScript != nil {
		err := serializeKVPairWithType(w, PsbtOutRedeemScript, nil,
			po.RedeemScript)
		if err != nil {
			return err
		}
	}
	if po.WitnessScript != nil {
		err := serializeKVPairWithType(w, PsbtOutWitnessScript, nil,
			po.WitnessScript)
		if err != nil {
			return err
		}
	}
	sort.Sort(Bip32Sorter(po.Bip32Derivation))
	for _, kd := range po.Bip32Derivation {
		err := serializeKVPairWithType(w, PsbtOutBip32Derivation,
			kd.PubKey,
			SerializeBIP32Derivation(kd.MasterKeyFingerprint,
				kd.Bip32Path))
		if err != nil {
			return err
		}
	}
	return nil
}

// Psbt is a set of 1 + N + M key-value pair lists, 1 global,
// defining the unsigned transaction structure with N inputs and M outputs.
// These key-value pairs can contain scripts, signatures,
// key derivations and other transaction-defining data.
type Psbt struct {
	UnsignedTx *wire.MsgTx // Deserialization of unsigned tx
	Inputs     []PInput
	Outputs    []POutput
	Unknowns   []Unknown // Data of unknown type at global scope
}

// validateUnsignedTx returns true if the transaction is unsigned.
// Note that more basic sanity requirements,
// such as the presence of inputs and outputs, is implicitly
// checked in the call to MsgTx.Deserialize()
func validateUnsignedTX(tx *wire.MsgTx) bool {
	for _, tin := range tx.TxIn {
		if len(tin.SignatureScript) != 0 || len(tin.Witness) != 0 {
			return false
		}
	}
	return true
}

// NewPsbtFromUnsignedTx creates a new Psbt struct, without
// any signatures (i.e. only the global section is non-empty).
func NewPsbtFromUnsignedTx(tx *wire.MsgTx) (*Psbt, error) {

	if !validateUnsignedTX(tx) {
		return nil, ErrInvalidRawTxSigned
	}

	inSlice := make([]PInput, len(tx.TxIn))
	outSlice := make([]POutput, len(tx.TxOut))
	unknownSlice := make([]Unknown, 0)

	retPsbt := Psbt{
		UnsignedTx: tx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}

	return &retPsbt, nil
}

// NewPsbt returns a new instance of a Psbt struct created
// by reading from a byte slice. If the format is invalid, an error
// is returned. If the argument b64 is true, the passed byte slice
// is decoded from base64 encoding before processing.
// NOTE To create a Psbt from one's own data, rather than reading
// in a serialization from a counterparty, one should use a psbt.Creator.
func NewPsbt(psbtBytes []byte, b64 bool) (*Psbt, error) {
	var err error
	if b64 {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(psbtBytes)))
		_, err = base64.StdEncoding.Decode(decoded, psbtBytes)
		if err != nil {
			return nil, err
		}
		psbtBytes = decoded
	}
	r := bytes.NewReader(psbtBytes)
	// The Psbt struct does not store the fixed magic bytes,
	// but they must be present or the serialization must
	// be explicitly rejected.
	var magic [5]byte
	if _, err = io.ReadFull(r, magic[:]); err != nil {
		return nil, err
	}
	if magic != psbtMagic {
		return nil, ErrInvalidMagicBytes
	}

	// Next we parse the GLOBAL section.
	// There is currently only 1 known key type, UnsignedTx.
	// We insist this exists first; unknowns are allowed, but
	// only after.
	keyint, keydata, err := getKey(r)
	if err != nil {
		return nil, err
	}
	if uint8(keyint) != PsbtGlobalUnsignedTx || keydata != nil {
		return nil, ErrInvalidPsbtFormat
	}
	value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
		"PSBT value")
	if err != nil {
		return nil, err
	}

	// Attempt to deserialize the unsigned transaction.
	msgTx := wire.NewMsgTx(2)
	err = msgTx.Deserialize(bytes.NewReader(value))
	if err != nil {
		return nil, err
	}
	if !validateUnsignedTX(msgTx) {
		return nil, ErrInvalidRawTxSigned
	}

	// parse any unknowns that may be present, break at separator
	unknownSlice := make([]Unknown, 0)
	for {
		keyint, keydata, err := getKey(r)
		if err != nil {
			return nil, ErrInvalidPsbtFormat
		}
		if keyint == -1 {
			break
		}
		value, err := wire.ReadVarBytes(r, 0, MaxPsbtValueLength,
			"PSBT value")
		if err != nil {
			return nil, err
		}
		keyintanddata := []byte{byte(keyint)}
		keyintanddata = append(keyintanddata, keydata...)
		newUnknown := Unknown{
			Key:   keyintanddata,
			Value: value,
		}
		unknownSlice = append(unknownSlice, newUnknown)
	}

	// Next we parse the INPUT section
	inSlice := make([]PInput, len(msgTx.TxIn))

	for i := range msgTx.TxIn {
		input := PInput{}
		err = input.deserialize(r)
		if err != nil {
			return nil, err
		}
		inSlice[i] = input
	}

	//Next we parse the OUTPUT section
	outSlice := make([]POutput, len(msgTx.TxOut))

	for i := range msgTx.TxOut {
		output := POutput{}
		err = output.deserialize(r)
		if err != nil {
			return nil, err
		}
		outSlice[i] = output
	}

	// Populate the new Psbt object
	newPsbt := Psbt{
		UnsignedTx: msgTx,
		Inputs:     inSlice,
		Outputs:    outSlice,
		Unknowns:   unknownSlice,
	}
	// Extended sanity checking is applied here
	// to make sure the externally-passed Psbt follows
	// all the rules.
	if err = newPsbt.SanityCheck(); err != nil {
		return nil, err
	}

	return &newPsbt, nil
}

// Serialize creates a binary serialization of the referenced
// Psbt struct with lexicographical ordering (by key) of the subsections
func (p *Psbt) Serialize() ([]byte, error) {

	serPsbt := []byte{}
	serPsbt = append(serPsbt, psbtMagic[:]...)

	// Create serialization of unsignedtx
	serializedTx := bytes.NewBuffer(make([]byte, 0,
		p.UnsignedTx.SerializeSize()))
	if err := p.UnsignedTx.Serialize(serializedTx); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err := serializeKVPairWithType(&buf, PsbtGlobalUnsignedTx,
		nil, serializedTx.Bytes())
	if err != nil {
		return nil, err
	}
	serPsbt = append(serPsbt, buf.Bytes()...)
	serPsbt = append(serPsbt, 0x00)

	for _, pInput := range p.Inputs {
		var buf bytes.Buffer
		err := pInput.serialize(&buf)
		if err != nil {
			return nil, err
		}
		serPsbt = append(serPsbt, buf.Bytes()...)
		serPsbt = append(serPsbt, 0x00)
	}

	for _, pOutput := range p.Outputs {
		var buf bytes.Buffer
		err := pOutput.serialize(&buf)
		if err != nil {
			return nil, err
		}
		serPsbt = append(serPsbt, buf.Bytes()...)
		serPsbt = append(serPsbt, 0x00)
	}

	return serPsbt, nil
}

// B64Encode returns the base64 encoding of the serialization of
// the current PSBT, or an error if the encoding fails.
func (p *Psbt) B64Encode() (string, error) {
	raw, err := p.Serialize()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// IsComplete returns true only if all of the inputs are
// finalized; this is particularly important in that it decides
// whether the final extraction to a network serialized signed
// transaction will be possible.
func (p *Psbt) IsComplete() bool {
	for i := 0; i < len(p.UnsignedTx.TxIn); i++ {
		if !isFinalized(p, i) {
			return false
		}
	}
	return true
}

// SanityCheck checks conditions on a PSBT to ensure that it obeys the
// rules of BIP174, and returns true if so, false if not.
func (p *Psbt) SanityCheck() error {

	if !validateUnsignedTX(p.UnsignedTx) {
		return ErrInvalidRawTxSigned
	}

	for _, tin := range p.Inputs {
		if !tin.IsSane() {
			return ErrInvalidPsbtFormat
		}
	}

	return nil
}
