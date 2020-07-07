package pbft

import (
	"bytes"
	"math/big"
	"testing"

	ecom "github.com/elastos/Elastos.ELA/common"
	"github.com/elastos/Elastos.ELA/core/types/payload"
	"github.com/elastos/Elastos.ELA/dpos/account"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/dpos"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
)

func TestReimportMirroredState(t *testing.T) {
	// Initialize a Clique chain with a single signer
	cfg := &params.PbftConfig{
		Producers: []string{
			"03bfd8bd2b10e887ec785360f9b329c2ae567975c784daca2f223cb19840b51914",
		},
	}
	PbftProtocolChanges := &params.ChainConfig{big.NewInt(1), big.NewInt(20), big.NewInt(0), nil, false, big.NewInt(0), common.Hash{}, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), nil, nil, nil, nil, nil, cfg, "", 0, "", 1, "test/keystore.dat", "123"}
	var (
		db     = rawdb.NewMemoryDatabase()
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		engine = New(cfg, PbftProtocolChanges.PbftKeyStore, []byte(PbftProtocolChanges.PbftKeyStorePassWord), "")
		signer = new(types.HomesteadSigner)
	)
	engine.IsCurrent = func() bool {
		return true
	}
	genspec := &core.Genesis{
		ExtraData: make([]byte, extraVanity + common.AddressLength + extraSeal),
		Alloc: map[common.Address]core.GenesisAccount{
			addr: {Balance: big.NewInt(1)},
		},
	}
	copy(genspec.ExtraData[extraVanity:], addr[:])
	genesis := genspec.MustCommit(db)

	// Generate a batch of blocks, each properly signed
	chain, _ := core.NewBlockChain(db, nil, PbftProtocolChanges, engine, engine, vm.Config{}, nil)
	defer chain.Stop()

	blocks, _ := core.GenerateChain(PbftProtocolChanges, genesis, engine, db, 3, func(i int, block *core.BlockGen) {
		// We want to simulate an empty middle block, having the same state as the
		// first one. The last is needs a state change again to force a reorg.
		if i != 1 {
			tx, err := types.SignTx(types.NewTransaction(block.TxNonce(addr), common.Address{0x00}, new(big.Int), params.TxGas, nil, nil), signer, key)
			if err != nil {
				panic(err)
			}
			block.AddTxWithChain(chain, tx)
		}
	})
	for i, block := range blocks {
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i-1].Hash()
		}

		confirm := createConfirm(block, engine.account)
		sealBuf := new(bytes.Buffer)
		confirm.Serialize(sealBuf)
		header.Extra = make([]byte, sealBuf.Len())
		copy(header.Extra[:], sealBuf.Bytes()[:])

		blocks[i] =block.WithSeal(header)
	}
	// Insert the first two blocks and make sure the chain is valid
	db = rawdb.NewMemoryDatabase()
	genspec.MustCommit(db)

	chain, _ = core.NewBlockChain(db, nil, PbftProtocolChanges, engine, engine, vm.Config{}, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[:2]); err != nil {
		t.Fatalf("failed to insert initial blocks: %v", err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != 2 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 2)
	}

	// Simulate a crash by creating a new chain on top of the database, without
	// flushing the dirty states out. Insert the last block, trigerring a sidechain
	// reimport.
	chain, _ = core.NewBlockChain(db, nil, PbftProtocolChanges, engine, engine, vm.Config{}, nil)
	defer chain.Stop()

	if _, err := chain.InsertChain(blocks[2:]); err != nil {
		t.Fatalf("failed to insert final block: %v", err)
	}
	if head := chain.CurrentBlock().NumberU64(); head != 3 {
		t.Fatalf("chain head mismatch: have %d, want %d", head, 3)
	}
}


func createConfirm(block *types.Block, ac account.Account) *payload.Confirm {
	hash := SealHash(block.Header())
	sealHash, _ := ecom.Uint256FromBytes(hash.Bytes())
	proposal, _ := dpos.StartProposal(ac, *sealHash, 0)

	proposalHash := proposal.Hash()
	vote, _ := dpos.StartVote(&proposalHash, true, ac)

	confirm := &payload.Confirm{
		Proposal: *proposal,
		Votes:    make([]payload.DPOSProposalVote, 0),
	}
	confirm.Votes = append(confirm.Votes, *vote)
	return confirm
}