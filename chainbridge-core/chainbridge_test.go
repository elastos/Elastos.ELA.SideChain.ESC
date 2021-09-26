package chainbridge_core

import (
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	"github.com/elastos/Elastos.ELA/common"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGetRandomProducers(t *testing.T) {
	cfg := &params.PbftConfig{
		Producers: []string{
		},
	}

	for i := 0; i < 36; i ++ {
		n := big.NewInt(int64(23 + i))
		h := common.Hash(n.Bytes())
		cfg.Producers = append(cfg.Producers, h.String())
	}

	expect := []string{
		"2326c2779c50a76bc27a64978173519d41de3604e82f53c1a94dcd8b1b6bdc39",
		"80903da4e6bbdf96e8ff6fc3966b0cfd355c7e860bdd1caa8e4722d9230e40ac",
		"2ec9b3cc687e93871f755d6c9962f62f351598ba779d9838aa2b68c8ef309f50",
		"a2215262d04d393d4e050d216733138a4e28c0b46375e84b7a34a218db8dc856",
		"bf1d535d30ebf4b7e639721faa475ea6e5a884f6468929101347e665b90fccdd",
		"c2908410ab0cbc5ef04a243a6c83ee07630a42cb1727401d384e94f755e320db",
		"d4880b6be079f51ee991b52f2e92636197de9c8a4063f69987eff619bb934872",
		"ef79a95edac9b7119192b7765ef48dc8c7ecc0db12b28d9f39b5b4dedcc98ccd",
		"0ca5765ffb7eb99901483c2cda1dd0209cef517e96e962b8c92c1668e5334d43",
		"fc62b10ec59efa8041f5a6c924d7c91572c1bbda280d9e01312b660804df1d47",
		"e368b5f8bac32462da14cda3a2c944365cbf7f34a5db8aa4e9d85abc21cf8f8a",
		"e344fcf046503fd53bb404197dac9c86405f8bd53b751e40bfa0e386df112f0f",
	}

	engine := pbft.New(cfg, "", []byte{}, "", 2)
	genspec := &core.Genesis{
		ExtraData: make([]byte, 128),
	}
	db     := rawdb.NewMemoryDatabase()
	PbftProtocolChanges := &params.ChainConfig{OldChainID: big.NewInt(1), ChainID: big.NewInt(20)}
	genspec.MustCommit(db)

	chain, _ := core.NewBlockChain(db, nil, PbftProtocolChanges, engine, engine, vm.Config{}, nil)
	defer chain.Stop()
	engine.SetBlockChain(chain)

	peers := GetRandomProducers(engine)
	for i, p := range peers {
		assert.Equal(t, common.BytesToHexString(p), expect[i])
	}
}
