package blocksigner

import (
	"math/rand"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
)

const defaultTestSignerNumber = 12

var (
	Signers map[common.Address]struct{}
	SelfIsProducer bool
)

func GetBlockSignerMaps(elaHeight uint64) *map[common.Address]struct{} {
	// TODO get from ELA
	return &Signers
}

func GetBlockSignersCount() int {
	// TODO get from ELA
	return len(Signers)
}

func ValidateSigner(elaHeight uint64, addr common.Address) bool {
	signers := GetBlockSignerMaps(elaHeight)
	_, ok := (*signers)[addr]
	return ok
}

func GenRandSingersFromTest() {
	Signers = make(map[common.Address]struct{})
	for i := 0; i < defaultTestSignerNumber; i++ {
		addr := common.Address{}
		rand.Read(addr[:])
		Signers[addr] = struct{}{}
	}
}
