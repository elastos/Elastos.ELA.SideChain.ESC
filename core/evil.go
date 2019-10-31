package core

import (
	"bytes"
	"encoding/binary"
	"errors"
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
	BlockHashes map[common.Hash]uint64 // key : hash of block, value:height of ela chain
}

type EvilSingerEvent struct {
	Singer    *common.Address
	Height    *big.Int
	ElaHeight uint64
	Hash      *common.Hash
}

// get evil signer signed blocks information by height
func (ei *EvilInfo) findBlockInfoByHeight(height *big.Int) *BlockInfo {
	for _, v := range ei.EvilBlocks {
		if v.Height.Cmp(height) == 0 {
			return v
		}
	}
	blockInfo := &BlockInfo{Height: height}
	index := len(ei.EvilBlocks)
	for i, v := range ei.EvilBlocks {
		if v.Height.Cmp(height) > 0 {
			index = i
		}
	}

	if index < len(ei.EvilBlocks) {
		evilBlocks := ei.EvilBlocks[:]
		ei.EvilBlocks = evilBlocks[:index]
		ei.EvilBlocks = append(ei.EvilBlocks, blockInfo)
		ei.EvilBlocks = append(ei.EvilBlocks, evilBlocks[index:]...)
	} else {
		ei.EvilBlocks = append(ei.EvilBlocks, blockInfo)
	}

	return blockInfo
}

// Remove old evil Signers when changing signers event comes from ela chain
func (signers *EvilSignersMap) RemoveOldEvilSigners(currentHeight *big.Int, rangeValue int64) error {
	if signers == nil {
		return nil
	}
	for k, v := range *signers {

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

// return lately height
func getLatelyElaHeight(heights []uint64) (uint64, error) {
	if len(heights) == 0 {
		return 0, errors.New("input array length is zero")
	}
	res := heights[0]
	for _, v := range heights {
		if v > res {
			res = v
		}
	}
	return res, nil
}

// update evil signers, send evil message to ela chain return de-duplication hashes
func (signers *EvilSignersMap) UpdateEvilSigners(addr common.Address, height *big.Int, hashes []*common.Hash,
	elaHeights []uint64) (map[common.Hash]uint64, error) {
	rangeValue := spv.GetBlockSignersCount()
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
		blockInfo.BlockHashes = make(map[common.Hash]uint64, 0)
	}
	addHashes := make(map[common.Hash]uint64, 0)
	for index, hash := range hashes {
		if _, ok := blockInfo.BlockHashes[*hash]; !ok {
			log.Info("Update evil signers", "evil info", "signer", addr.String(), "height",
				height.String(), "blockHash", hash.String())
			blockInfo.BlockHashes[*hash] = elaHeights[index]
			addHashes[*hash] = elaHeights[index]
		}
	}
	return addHashes, nil
}

// Return whether is to much evil signers.
func (signers *EvilSignersMap) IsDanger(currentHeight *big.Int, threshold int) bool {
	if signers == nil || threshold <= 0 {
		return false
	}
	count := 0
	signersLen := spv.GetBlockSignersCount()
	earliestHeight := new(big.Int).Sub(currentHeight, big.NewInt(int64(signersLen)))
	for _, v := range *signers {
		index := len(v.EvilBlocks) - 1
		for {
			if index < 0 {
				break
			}
			if v.EvilBlocks[index].Height.Cmp(currentHeight) <= 0 && v.EvilBlocks[index].Height.Cmp(earliestHeight) > 0 {
				count++
			}
			index--
		}

	}
	return count > threshold
}

func (signers *EvilSignersMap) AddEvilSingerEvents(evilEvents []*EvilSingerEvent) []error {
	errs := make([]error, len(evilEvents))
	for i, v := range evilEvents {
		if v.Singer == nil {
			continue
		}
		_, err := signers.UpdateEvilSigners(*v.Singer, v.Height, []*common.Hash{v.Hash}, []uint64{v.ElaHeight})
		errs[i] = err
	}
	return errs
}

func (signers *EvilSignersMap) GetEvilSignerEvents() (res []*EvilSingerEvent) {
	for singer, infos := range *signers {
		for _, blockInfo := range infos.EvilBlocks {
			for hash, v := range blockInfo.BlockHashes {
				copyHash := common.Hash{}
				copy(copyHash[:], hash[:])
				res = append(res, &EvilSingerEvent{&singer, blockInfo.Height,
					v, &copyHash})
			}

		}

	}
	return res
}

// Parse Ela chain height from header extra
func ParseElaHeightFromHead(head *types.Header) (uint64, error) {
	length := len(head.Extra)
	if length < 105 {
		return 0, errors.New("header's extra length is to short")
	}
	heightBytes := head.Extra[length-73 : length-65]
	return binary.LittleEndian.Uint64(heightBytes), nil
}

// whether the block was created by evil signer.
func IsNeedStopChain(headerNew, headerOld *types.Header, engine consensus.Engine, signers *EvilSignersMap,
	journal *EvilJournal) bool {

	hashOld := headerOld.Hash()
	hashNew := headerNew.Hash()

	elaHeightOld, _ := ParseElaHeightFromHead(headerOld)
	elaHeightNew, _ := ParseElaHeightFromHead(headerNew)

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

	addHashes, err := signers.UpdateEvilSigners(singerNew, headerNew.Number, []*common.Hash{&hashOld, &hashNew},
		[]uint64{elaHeightOld, elaHeightNew})
	if err != nil {
		return false
	}

	if journal != nil {
		for hash, height := range addHashes {
			log.Info("EvilSignerEvent", "Insert", "Singer", singerNew.String(), "Number:",
				headerNew.Number.Uint64(), "Hash:", hash.String())
			journal.Insert(&EvilSingerEvent{&singerNew, headerNew.Number, height, &hash})
		}
	}

	if signers.IsDanger(headerNew.Number, spv.GetBlockSignersCount()*2/3) {
		return true
	}
	return false
}
