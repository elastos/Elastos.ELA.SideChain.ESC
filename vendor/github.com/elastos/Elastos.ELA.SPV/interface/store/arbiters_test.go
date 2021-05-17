package store

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

func TestArbiters(t *testing.T) {
	dataDir := "spv_test"
	os.RemoveAll(dataDir)

	db, err := leveldb.OpenFile(filepath.Join(dataDir, "store"), nil)
	if err != nil {
		println(err.Error())
	}
	originArbiters := []string{
		"02089d7e878171240ce0e3633d3ddc8b1128bc221f6b5f0d1551caa717c7493062",
		"0268214956b8421c0621d62cf2f0b20a02c2dc8c2cc89528aff9bd43b45ed34b9f",
		"03cce325c55057d2c8e3fb03fb5871794e73b85821e8d0f96a7e4510b4a922fad5",
		"02661637ae97c3af0580e1954ee80a7323973b256ca862cfcf01b4a18432670db4",
		"027d816821705e425415eb64a9704f25b4cd7eaca79616b0881fc92ac44ff8a46b",
		"02d4a8f5016ae22b1acdf8a2d72f6eb712932213804efd2ce30ca8d0b9b4295ac5",
		"029a4d8e4c99a1199f67a25d79724e14f8e6992a0c8b8acf102682bd8f500ce0c1",
		"02871b650700137defc5d34a11e56a4187f43e74bb078e147dd4048b8f3c81209f",
		"02fc66cba365f9957bcb2030e89a57fb3019c57ea057978756c1d46d40dfdd4df0",
		"03e3fe6124a4ea269224f5f43552250d627b4133cfd49d1f9e0283d0cd2fd209bc",
		"02b95b000f087a97e988c24331bf6769b4a75e4b7d5d2a38105092a3aa841be33b",
		"02a0aa9eac0e168f3474c2a0d04e50130833905740a5270e8a44d6c6e85cf6d98c",
	}
	var origincrcs [][]byte
	for _, v := range originArbiters {
		crc, _ := hex.DecodeString(v)
		origincrcs = append(origincrcs, crc)
	}
	arbiters := NewArbiters(db, origincrcs, 36)
	crcPublicKey := []string{
		"03C3A4A137EB63B05E9F14070639E680DF78616D70EE1BA52B0759236B4B698CDB",
		"03B97154758B8B1A044DB774A4A19E1591DC165A0FA24F74388FBDF0EFDB919CFA",
	}

	normalPublicKey := []string{
		"02713D40469D5AAF54FB622791936B4C21DABB62315041C292E2DCEC97AE1FBA69",
		"0276305327217E42CF6892536251354A029A9B814C3A65492B033504D29844CCB1",
		"03D3787D8904E82AFC1B83687AC0FEF919A1E96A1C78FB049904F553C3102049B4",
		"03DD46B1E064A0BD0BA9A0FEFE58E4703EB44189D137462F4FA5181EE42A8F61AE",
	}
	var crcs [][]byte
	for _, v := range crcPublicKey {
		crc, _ := hex.DecodeString(v)
		crcs = append(crcs, crc)
	}
	var normal [][]byte
	for _, v := range normalPublicKey {
		nor, _ := hex.DecodeString(v)
		normal = append(normal, nor)
	}
	err = arbiters.Put(402, crcs, normal)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}

	err = arbiters.Put(403, crcs, normal)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}
	crc, nor, err := arbiters.Get()
	if err != nil {
		t.Errorf("get arbiter error %s", err.Error())
		return
	}
	if !checkExist(crc, crcs) {
		t.Errorf("crc arbiter can not be found")
		return
	}
	if !checkExist(nor, normal) {
		t.Errorf("normal arbiter can not be found")
		return
	}

	crcscopy := make([][]byte, len(crcs))
	copy(crcscopy, crcs)
	append1, _ := hex.DecodeString("02ECF46B0DE8435DD4E4A93341763F3DDBF12C106C0BE00363B114EFE90F5D2F58")
	crcs = append(crcs, append1)

	err = arbiters.Put(405, crcs, normal)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}
	crc, nor, err = arbiters.Get()
	if err != nil {
		t.Errorf("get arbiter error %s", err.Error())
		return
	}
	if !checkExist(crc, crcs) {
		t.Errorf("crc arbiter can not be found")
		return
	}
	if !checkExist(nor, normal) {
		t.Errorf("normal arbiter can not be found")
		return
	}

	err = arbiters.Put(407, crcs, normal)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}
	crc, nor, err = arbiters.Get()
	if err != nil {
		t.Errorf("get arbiter error %s", err.Error())
		return
	}
	if !checkExist(crc, crcs) {
		t.Errorf("crc arbiter can not be found")
		return
	}
	if !checkExist(nor, normal) {
		t.Errorf("normal arbiter can not be found")
		return
	}

	err = arbiters.Put(407, crcscopy, normal)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}

	// batch put
	batch := new(leveldb.Batch)
	err = arbiters.BatchPut(602, crcs, normal, batch)
	if err != nil {
		t.Errorf("put arbiter error %s", err.Error())
		return
	}
	arbiters.CommitBatch(batch)

	crc, nor, err = arbiters.Get()
	if err != nil {
		t.Errorf("get arbiter error %s", err.Error())
		return
	}
	if !checkExist(crc, crcs) {
		t.Errorf("crc arbiter can not be found")
		return
	}
	if !checkExist(nor, normal) {
		t.Errorf("normal arbiter can not be found")
		return
	}

	crc, nor, err = arbiters.GetByHeight(10000)
	if !assert.Error(t, err, "get arbiter error invalid height") {
		t.FailNow()
	}

	crc, nor, err = arbiters.GetByHeight(400)
	if err != nil {
		t.Errorf("get arbiter error %s", err.Error())
		return
	}
	if !checkExist(crc, origincrcs) {
		t.Errorf("crc arbiter can not be found")
		return
	}




}

func checkExist(target [][]byte, src [][]byte) bool {
	for _, v := range target {
		var find bool
		for _, _v := range src {
			if bytes.Equal(v, _v) {
				find = true
				break
			}
		}
		if find == false {
			return false
		}
	}
	return true
}
