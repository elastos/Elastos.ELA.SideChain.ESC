package core

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"testing"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/clique"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/ethdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"
)

var (
	extraVanity    = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal      = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
	extraElaHeight = 8  // Fixed height of ela chain height with LitterEnd encode

)

// testerAccountPool is a pool to maintain currently active tester accounts,
// mapped from textual names used in the tests below to actual Ethereum private
// keys capable of signing transactions.
type testerAccountPool struct {
	accounts map[string]*ecdsa.PrivateKey
}

func newTesterAccountPool() *testerAccountPool {
	return &testerAccountPool{
		accounts: make(map[string]*ecdsa.PrivateKey),
	}
}

func (ap *testerAccountPool) address(account string) common.Address {
	// Return the zero account for non-addresses
	if account == "" {
		return common.Address{}
	}
	// Ensure we have a persistent key for the account
	if ap.accounts[account] == nil {
		ap.accounts[account], _ = crypto.GenerateKey()
	}
	// Resolve and return the Ethereum address
	return crypto.PubkeyToAddress(ap.accounts[account].PublicKey)
}

// sign calculates a Clique digital signature for the given block and embeds it
// back into the header.
func (ap *testerAccountPool) sign(header *types.Header, signer string, sigHash func(header *types.Header) common.Hash) {
	// Ensure we have a persistent key for the signer
	if ap.accounts[signer] == nil {
		ap.accounts[signer], _ = crypto.GenerateKey()
	}
	// Sign the header and embed the signature in extra data
	sig, _ := crypto.Sign(sigHash(header).Bytes(), ap.accounts[signer])
	copy(header.Extra[len(header.Extra)-extraSeal:], sig)
}

func TestRemoveOldEvilSigners(t *testing.T) {
	evilMaps := &EvilSignersMap{}

	for i := 0; i < 10; i++ {
		signersNum := rand.Intn(10) + 1
		spv.Signers = make(map[common.Address]struct{})
		signers := make([]common.Address, 0)
		for {
			if signersNum == 0 {
				break
			}
			signersNum--
			addr := common.Address{}
			if _, err := rand.Read(addr[:]); err != nil {
				continue
			}
			signers = append(signers, addr)
			spv.Signers[addr] = struct{}{}
		}
		signersNum = len(signers)
		evilEventsNum := rand.Intn(10) + signersNum + 1
		index := 1
		for {
			if index >= evilEventsNum {
				break
			}

			evilMaps.UpdateEvilSigners(signers[index%signersNum], big.NewInt(int64(index)), []*common.Hash{&common.Hash{}})
			index++
		}

		if len(*evilMaps) != signersNum {

			t.Errorf("Wrong result, detail: signersNumber:%v, evilEventsNum: %v, evilSigners: %v",
				signersNum, evilEventsNum, len(*evilMaps))
		}

	}

}

func TestEvilSigners(t *testing.T) {
	signerkeys := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N"}
	accounts := newTesterAccountPool()
	signers := make([]common.Address, len(signerkeys))
	spv.Signers = make(map[common.Address]struct{})
	for j, key := range signerkeys {
		signers[j] = accounts.address(key)
		spv.Signers[signers[j]] = struct{}{}
	}
	for j := 0; j < len(signers); j++ {
		for k := j + 1; k < len(signers); k++ {
			if bytes.Compare(signers[j][:], signers[k][:]) > 0 {
				signers[j], signers[k] = signers[k], signers[j]
			}
		}
	}
	// Create the genesis block with the initial set of signers
	genesis := &Genesis{
		ExtraData: make([]byte, extraVanity+common.AddressLength*len(signers)+extraSeal+extraElaHeight),
	}
	for j, signer := range signers {
		copy(genesis.ExtraData[extraVanity+j*common.AddressLength:], signer[:])
	}
	db := ethdb.NewMemDatabase()
	genesis.Commit(db)
	config := *params.TestChainConfig
	config.Clique = &params.CliqueConfig{
		Period: 1,
		Epoch:  30000,
	}
	engine := clique.New(config.Clique, db)
	engine.SetFakeDiff(true)
	blocks, _ := GenerateChain(&config, genesis.ToBlock(db), engine, db, len(signerkeys)*4, nil)
	blocksevil, _ := GenerateChain(&config, genesis.ToBlock(db), engine, db, len(signerkeys), nil)
	diffInTurn := big.NewInt(2)
	for j, block := range blocks {
		// Geth the header and prepare it for signing
		header := block.Header()
		if j > 0 {
			header.ParentHash = blocks[ j-1].Hash()
		}
		header.Extra = make([]byte, extraVanity+extraSeal+extraElaHeight)
		header.Difficulty = diffInTurn // Ignored, we just need a valid number
		// Generate the signature, embed it into the header and the block
		index := j % len(signerkeys)
		accounts.sign(header, signerkeys[index], engine.SealHash)
		blocks[j] = block.WithSeal(header)
	}

	for j, block := range blocksevil {
		// Geth the header and prepare it for signing
		header := block.Header()

		header.GasLimit = header.GasLimit + uint64(j*12)
		if j > 0 {
			header.ParentHash = blocks[2*len(signerkeys)+j-1].Hash()
		}
		header.Number = new(big.Int).SetUint64(blocks[2*len(signerkeys)+j ].NumberU64())
		header.Time = new(big.Int).SetUint64(blocks[2*len(signerkeys)+j ].Time().Uint64() + 1)
		header.Extra = make([]byte, extraVanity+extraSeal+extraElaHeight)
		header.Difficulty = diffInTurn // Ignored, we just need a valid number
		// Generate the signature, embed it into the header and the block
		index := j % len(signerkeys)

		accounts.sign(header, signerkeys[index], engine.SealHash)
		blocksevil[j] = block.WithSeal(header)

	}

	//blocks = append(blocks, blocksevil[1:]...)
	chain, err := NewBlockChain(db, nil, &config, engine, vm.Config{}, nil)
	//fmt.Println(chain.CurrentBlock().Number().String())
	if err != nil {
		t.Error("create chain fail", err)
	}

	for _, block := range blocks {
		chain.InsertChain(types.Blocks{block})
	}

	for _, block := range blocksevil[1:] {
		chain.InsertChain(types.Blocks{block})
	}

	if !chain.evilSigners.IsDanger(len(signerkeys) / 2) {
		t.Error("Count evil signers wrong")
	}

}
