package eth

import (
	"bytes"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus/pbft"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/params"
	ecom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"
	"github.com/stretchr/testify/assert"

	"math/big"
	"testing"
)

func TestBlockfork(t *testing.T) {
	t.Skip("TestBlockfork skip")
	cfg := &params.PbftConfig{
		Producers: []string{
			"03bfd8bd2b10e887ec785360f9b329c2ae567975c784daca2f223cb19840b51914",
		},
	}
	PbftProtocolChanges := &params.ChainConfig{OldChainID: big.NewInt(1), ChainID: big.NewInt(20), HomesteadBlock: big.NewInt(0), DAOForkBlock: nil, DAOForkSupport: false, EIP150Block: big.NewInt(0), EIP150Hash: common.Hash{}, EIP155Block: big.NewInt(0), EIP158Block: big.NewInt(0), ChainIDBlock: big.NewInt(0), ByzantiumBlock: big.NewInt(0), ConstantinopleBlock: big.NewInt(0), PetersburgBlock: big.NewInt(0), IstanbulBlock: nil, EWASMBlock: nil, PBFTBlock: big.NewInt(0), Ethash: nil, Clique: nil, Pbft: cfg, BlackContractAddr: "", PassBalance: 0, EvilSignersJournalDir: "", PreConnectOffset: 1, PbftKeyStore: "../consensus/pbft/test/keystore.dat", PbftKeyStorePassWord: "123"}
	var (
		db          = rawdb.NewMemoryDatabase()
		key, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr        = crypto.PubkeyToAddress(key.PublicKey)
		extraVanity = 32
		signer      = new(types.HomesteadSigner)
		engine      = pbft.New(PbftProtocolChanges, "")
	)
	eth := &Ethereum{
		engine: engine,
	}
	genspec := &core.Genesis{
		ExtraData: make([]byte, extraVanity+common.AddressLength+65),
		Alloc: map[common.Address]core.GenesisAccount{
			addr: {Balance: big.NewInt(1)},
		},
	}
	copy(genspec.ExtraData[extraVanity:], addr[:])
	genesis := genspec.MustCommit(db)

	// Generate a batch of blocks, each properly signed
	chain, _ := core.NewBlockChain(db, nil, PbftProtocolChanges, engine, engine, vm.Config{}, eth.shouldPreserve)
	defer chain.Stop()
	eth.blockchain = chain
	blocks, _ := core.GenerateChain(PbftProtocolChanges, genesis, engine, db, 3, func(i int, block *core.BlockGen) {
		block.SetDifficulty(big.NewInt(2))
	})

	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		var confirm = createConfirm(block, engine.GetDposAccount(), 1)
		sealBuf := new(bytes.Buffer)
		confirm.Serialize(sealBuf)
		header.Extra = make([]byte, sealBuf.Len())
		copy(header.Extra[:], sealBuf.Bytes()[:])

		blocks[i] = block.WithSeal(header)
	}
	if _, err := chain.InsertChain(blocks[:3]); err != nil {
		t.Fatalf("failed to insert initial blocks: %v", err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != 3 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 3)
	}

	parent := chain.GetBlockByNumber(2)
	forkblocks, _ := core.GenerateChain(PbftProtocolChanges, parent, engine, db, 1, func(i int, block *core.BlockGen) {
		tx, err := types.SignTx(types.NewTransaction(block.TxNonce(addr), common.Address{0x00}, new(big.Int), params.TxGas, nil, nil), signer, key)
		if err != nil {
			panic(err)
		}
		block.AddTxWithChain(chain, tx)
		block.SetDifficulty(big.NewInt(2))
	})

	for i, block := range forkblocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}
		var confirm = createConfirm(block, engine.GetDposAccount(), 2)
		sealBuf := new(bytes.Buffer)
		confirm.Serialize(sealBuf)
		header.Extra = make([]byte, sealBuf.Len())
		copy(header.Extra[:], sealBuf.Bytes()[:])

		forkblocks[i] = block.WithSeal(header)
	}

	b1 := chain.CurrentBlock()
	assert.Equal(t, b1.NumberU64(), uint64(3))
	assert.Equal(t, b1.Transactions().Len(), 0)
	if _, err := chain.InsertChain(forkblocks); err != nil {
		t.Fatalf("failed to insert fork blocks: %v", err)
	}
	b2 := chain.CurrentBlock()
	assert.Equal(t, b2.NumberU64(), b1.NumberU64())
	assert.Equal(t, b2.Transactions().Len(), 1)
	assert.NotEqual(t, b1.Hash().String(), b2.Hash().String())
}

func createConfirm(block *types.Block, ac account.Account, viewOffset uint32) *payload.Confirm {
	hash := pbft.SealHash(block.Header())
	sealHash, _ := ecom.Uint256FromBytes(hash.Bytes())
	proposal, _ := dpos.StartProposal(ac, *sealHash, viewOffset)
	proposalHash := proposal.Hash()
	confirm := &payload.Confirm{
		Proposal: *proposal,
		Votes:    make([]payload.DPOSProposalVote, 0),
	}
	for i := 1; i <= 8; i++ {
		vote, _ := dpos.StartVote(&proposalHash, true, ac)
		confirm.Votes = append(confirm.Votes, *vote)
	}
	return confirm
}
