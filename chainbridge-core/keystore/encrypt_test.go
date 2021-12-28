// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package keystore

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/crypto/secp256k1"
)

func TestEncryptAndDecrypt(t *testing.T) {
	password := []byte("noot")
	msg := []byte("helloworld")

	ciphertext, err := Encrypt(msg, password)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Decrypt(ciphertext, password)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, res) {
		t.Fatalf("Fail to decrypt: got %x expected %x", res, msg)
	}
}

func TestEncryptAndDecryptKeypair(t *testing.T) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		t.Fatal(err)
	}

	kp, err := secp256k1.NewKeypairFromPrivateKey(buf)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("noot")

	data, err := EncryptKeypair(kp, password)
	if err != nil {
		t.Fatal(err)
	}

	res, err := DecryptKeypair(kp.PublicKey(), data, password, "secp256k1")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(kp, res) {
		t.Fatalf("Fail: got %#v expected %#v", res, kp)
	}
}

func createTestFile(t *testing.T) (*os.File, string) {
	filename := "./test_key"

	fp, err := filepath.Abs(filename)
	if err != nil {
		t.Fatal(err)
	}

	file, err := os.Create(fp)
	if err != nil {
		t.Fatal(err)
	}

	return file, fp
}
