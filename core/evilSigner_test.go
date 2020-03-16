package core

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus/clique"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/vm"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/params"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/blocksigner"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/rawdb"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/crypto"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"
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
	copy(header.Extra[len(header.Extra)-spv.ExtraSeal:], sig)
}

func GetSigners(count int64) []common.Address {
	blocksigner.Signers = make(map[common.Address]struct{})
	signers := make([]common.Address, 0)
	for i := int64(0); i < count; i++ {
		addr := common.Address{}
		if _, err := rand.Read(addr[:]); err != nil {
			continue
		}
		signers = append(signers, addr)
		blocksigner.Signers[addr] = struct{}{}
	}
	return signers
}

func TestRemoveOldEvilSigners(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 10; i++ {
		evilMaps := &EvilSignersMap{}
		signersNum := rand.Intn(10) + 1
		signers := GetSigners(int64(signersNum))
		signersNum = len(signers)
		evilEventsNum := rand.Intn(10) + signersNum + 1
		index := 1
		for {
			if index >= evilEventsNum {
				break
			}
			evilMaps.UpdateEvilSigners(signers[index%signersNum], big.NewInt(int64(index)),
				[]*common.Hash{&common.Hash{}}, []uint64{0})
			index++
		}
		if len(*evilMaps) != signersNum {
			t.Errorf("Wrong UpdateEvilSigners result, detail: signersNumber:%v, evilEventsNum: %v, evilSigners: %v",
				signersNum, evilEventsNum, len(*evilMaps))
		}

		for index = 0; index < evilEventsNum; index++ {
			evilMaps.RemoveOldEvilSigners(big.NewInt(int64(signersNum + index + 1)), int64(signersNum))
		}

		if len(*evilMaps) != 0 {
			t.Errorf("Wrong RemoveOldEvilSigners result, detail: signersNumber:%v, evilEventsNum: %v, evilSigners: %v",
				signersNum, evilEventsNum, len(*evilMaps))
		}
	}
}

func TestEvilSigners(t *testing.T)  {
	signerKeys := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "M", "N"}
	accounts := newTesterAccountPool()
	signers := make([]common.Address, len(signerKeys))
	blocksigner.Signers = make(map[common.Address]struct{})
	for j, key := range signerKeys {
		signers[j] = accounts.address(key)
		blocksigner.Signers[signers[j]] = struct{}{}
	}
	for i := 0; i < len(signers); i++ {
		for j := i + 1; j < len(signers); j++ {
			if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
				signers[i], signers[j] = signers[j], signers[i]
			}
		}
	}
	// Create the genesis block with the initial set of signers
	genesis := &Genesis{
		ExtraData: make([]byte, spv.ExtraVanity+common.AddressLength*len(signers)+spv.ExtraSeal+spv.ExtraElaHeight),
	}
	for j, signer := range signers {
		copy(genesis.ExtraData[spv.ExtraVanity+j*common.AddressLength:], signer[:])
	}
	db := rawdb.NewMemoryDatabase()
	genesis.Commit(db)
	config := *params.TestChainConfig
	config.Clique = &params.CliqueConfig{
		Period: 1,
		Epoch:  30000,
	}
	engine := clique.New(config.Clique, db)
	engine.SetFakeDiff(true)
	blocks, _ := GenerateChain(&config, genesis.ToBlock(db), engine, db, len(signerKeys)*3, nil)
	blocksevil, _ := GenerateChain(&config, genesis.ToBlock(db), engine, db, len(signerKeys), nil)
	diffInTurn := big.NewInt(2)

	for i, block := range blocks {
		// Get the header and prepare it for signing
		header := block.Header()
		if i > 0 {
			header.ParentHash = blocks[i - 1].Hash()
		}
		header.Extra = make([]byte, spv.ExtraVanity + spv.ExtraSeal + spv.ExtraElaHeight)
		header.Difficulty = diffInTurn  // Ignored, we just need a valid number
		// Generate the signature, embed it into the header and the block
		index := i % len(signerKeys)
		accounts.sign(header, signerKeys[index], engine.SealHash)
		blocks[i] = block.WithSeal(header)
	}
	for i, block := range blocksevil {
		// Geth the header and prepare it for signing
		header := block.Header()

		header.GasLimit = header.GasLimit + uint64(i*12)
		if i > 0 {
			header.ParentHash = blocks[2*len(signerKeys)+i-1].Hash()
		}
		header.Number = new(big.Int).SetUint64(blocks[2*len(signerKeys) + i].NumberU64())
		header.Time = blocks[2*len(signerKeys) + i].Time() + 1
		header.Extra = make([]byte, spv.ExtraVanity + spv.ExtraSeal + spv.ExtraElaHeight)
		header.Difficulty = diffInTurn // Ignored, we just need a valid number
		// Generate the signature, embed it into the header and the block
		index := i % len(signerKeys)

		accounts.sign(header, signerKeys[index], engine.SealHash)
		blocksevil[i] = block.WithSeal(header)
	}
	chain, err := NewBlockChain(db, nil, &config, engine, vm.Config{}, nil)
	if err != nil {
		t.Error("create chain fail", err)
	}

	for _, block := range blocks {
		chain.InsertChain(types.Blocks{block})
	}

	for _, block := range blocksevil[1:] {
		chain.InsertChain(types.Blocks{block})
	}

	if !chain.evilSigners.IsDanger(big.NewInt(int64(len(signerKeys)*3)), len(signerKeys)*2/3) {
		t.Error("Count evil signers wrong")
	}
}