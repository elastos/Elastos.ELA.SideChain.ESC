package core

import (
	"bytes"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ETH/common"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/consensus"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA.SideChain.ETH/spv"
)

type EvilSignersMap map[common.Address]*EvilInfo

type EvilInfo struct {
	EvilBlocks []*BlockInfo
}

type BlockInfo struct {
	Height      *big.Int
	BlockHashes map[common.Hash]struct{}
}

type EvilSingerEvent struct {
	Singer *common.Address
	Height *big.Int
	Hash   *common.Hash
}

// get evil signer signed blocks information by height
func (ei *EvilInfo) findBlockInfoByHeight(height *big.Int) *BlockInfo {
	for _, v := range ei.EvilBlocks {
		if v.Height.Cmp(height) == 0 {
			return v
		}
	}
	blockInfo := &BlockInfo{Height: height}
	ei.EvilBlocks = append(ei.EvilBlocks, blockInfo)
	return blockInfo
}

// Remove old evil Signers when changing signers event comes from ela chain
func (signers *EvilSignersMap) RemoveOldEvilSigners(currentHeight *big.Int, rangeValue int64) error {
	signersNew := spv.GetBlockSignerMaps()
	if signers == nil {
		return nil
	}
	for k, v := range *signers {
		if _, ok := (*signersNew)[k]; !ok {
			log.Info("Remove evil signers", "old signer", k.String())
			delete(*signers, k)
			continue
		}

		if currentHeight == nil || rangeValue <= 0 {
			continue
		}
		length := len(v.EvilBlocks)
		height := v.EvilBlocks[length-1].Height
		res := new(big.Int).Sub(currentHeight, height)
		if res.Int64() > rangeValue {
			log.Info("Remove evil signers", "height to early", k.String())
			delete(*signers, k)
		}
	}
	return nil

}

// update evil signers, send evil message to ela chain return de-duplication hashes
func (signers *EvilSignersMap) UpdateEvilSigners(addr common.Address, height *big.Int, hashes []*common.Hash) ([]*common.Hash, error) {
	rangeValue := spv.GetBlockSignerLen()
	signers.RemoveOldEvilSigners(height, int64(rangeValue))

	evilInfo := &EvilInfo{}
	if v, ok := (*signers)[addr]; ok {
		evilInfo = v
	} else {
		(*signers)[addr] = evilInfo
		spv.SendEvilProof(addr, nil)
	}
	blockInfo := evilInfo.findBlockInfoByHeight(height)
	if blockInfo.BlockHashes == nil {
		blockInfo.BlockHashes = make(map[common.Hash]struct{}, 0)
	}
	addHashes := make([]*common.Hash, 0)
	for _, hash := range hashes {
		if _, ok := blockInfo.BlockHashes[*hash]; !ok {
			log.Info("Update evil signers", "evil info", "signer", addr.String(), "height", height.String(), "blockHash", hash.String())
			blockInfo.BlockHashes[*hash] = struct{}{}
			addHashes = append(addHashes, hash)

		}
	}
	return addHashes, nil
}

// Return whether is to much evil signers.
func (signers *EvilSignersMap) IsDanger(threshold int) bool {
	if signers == nil || threshold <= 0 {
		return false
	}
	return len(*signers) > threshold
}

func (signers *EvilSignersMap) AddEvilSingerEvents(evilEvents []*EvilSingerEvent) []error {
	errs := make([]error, len(evilEvents))
	for i, v := range evilEvents {
		if v.Singer == nil {
			continue
		}
		_, err := signers.UpdateEvilSigners(*v.Singer, v.Height, []*common.Hash{v.Hash})
		errs[i] = err
	}
	return errs
}

func (signers *EvilSignersMap) GetEvilSignerEvents() (res []*EvilSingerEvent) {
	for singer, infos := range *signers {
		for _, blockInfo := range infos.EvilBlocks {
			for hash, _ := range blockInfo.BlockHashes {
				copyHash := common.Hash{}
				copy(copyHash[:], hash[:])
				res = append(res, &EvilSingerEvent{&singer, blockInfo.Height, &copyHash})
			}

		}

	}
	return res
}

// whether the block was created by evil signer.
func IsNeedStopChain(headerNew, headerOld *types.Header, engine consensus.Engine, signers *EvilSignersMap,
	journal *EvilJournal) bool {

	hashOld := headerOld.Hash()
	hashNew := headerNew.Hash()

	if bytes.Equal(hashNew[:], hashOld[:]) {
		return false
	}
	singerOld, err := engine.Author(headerOld)
	if err != nil {
		return false
	}
	singerNew, err := engine.Author(headerNew)
	if err != nil {
		return false
	}
	if !bytes.Equal(singerNew[:], singerOld[:]) {
		return false
	}

	addHashes, err := signers.UpdateEvilSigners(singerNew, headerNew.Number, []*common.Hash{&hashOld, &hashNew})
	if err != nil {
		return false
	}

	if journal != nil {
		for _, hash := range addHashes {
			log.Info("EvilSignerEvent", "Insert", "Singer", singerNew.String(), "Number:", headerNew.Number.Uint64(), "Hash:", hash.String())
			journal.Insert(&EvilSingerEvent{&singerNew, headerNew.Number, hash})
		}
	}

	if signers.IsDanger(spv.GetBlockSignerLen() / 2) {
		return true
	}
	return false
}
