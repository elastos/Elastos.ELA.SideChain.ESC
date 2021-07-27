package core

import (
	"bytes"
	"io/ioutil"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
)

func TestEvilJoural(t *testing.T) {
	dataDir, err := ioutil.TempDir("", "elaeth_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dataDir)
	joural := NewEvilJournal(dataDir)
	joural.Rotate(nil)
	eventsNumber := rand.Intn(10) + 1
	events := make([]*EvilSingerEvent, eventsNumber)
	index := 0
	for {
		if eventsNumber == index {
			break
		}

		addr := common.Address{}
		height := big.NewInt(rand.Int63())
		hash := common.Hash{}
		if _, err := rand.Read(addr[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(hash[:]); err != nil {
			t.Fatal(err)
		}
		events[index] = &EvilSingerEvent{&addr, height, height.Uint64(), &hash}
		joural.Insert(events[index])
		index++
	}

	joural.Close()

	eventsNew := make([]*EvilSingerEvent, 0)

	add := func(events []*EvilSingerEvent) []error {
		errors := make([]error, len(events))
		for _, v := range events {
			eventsNew = append(eventsNew, v)
		}

		return errors
	}
	joural.Load(add)

	if len(eventsNew) != len(events) {
		t.Errorf("Write and Read events numbers are not equal!")
	}

	for i, v := range events {

		if !bytes.Equal(v.Hash[:], eventsNew[i].Hash[:]) {
			t.Errorf("Write and Read event are not equal!")
		}

		if !bytes.Equal(v.Singer[:], eventsNew[i].Singer[:]) {
			t.Errorf("Write and Read event are not equal!")
		}

		if v.Height.Cmp(eventsNew[i].Height) != 0 {
			t.Errorf("Write and Read event are not equal!")
		}

		if v.ElaHeight != eventsNew[i].ElaHeight {
			t.Errorf("Write and Read event are not equal!")
		}

	}

}
