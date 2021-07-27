package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/consensus"
	"math/big"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/blocksigner"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/core/types"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/spv"
)

//Evidence of evil signers
type EvilSignersMap map[common.Address]*Evidences
type Evidences []*EvilEvidence

// Eviddence of double sign
type EvilEvidence struct {
	Height      *big.Int               // height of side chain
	BlockOnHeight map[common.Hash]uint64 // key : hash of block, value:height of ela chain
}

func NewEvilEvidence(height *big.Int) *EvilEvidence {
	r := &EvilEvidence{Height:height}
	r.BlockOnHeight = make(map[common.Hash] uint64, 0)
	return r
}

type EvilSingerEvent struct {
	Singer    *common.Address
	Height    *big.Int
	ElaHeight uint64
	Hash      *common.Hash
}

// get evil signer signed blocks information by height
func (ei *Evidences) getEvidence(height *big.Int) *EvilEvidence {
	for _, v := range *ei {
		if v.Height.Cmp(height) == 0 {
			return v
		}
	}
	return ei.addEvidence(height)
}

func (ei *Evidences) addEvidence(height *big.Int) *EvilEvidence {
	index := len(*ei)
	for i, v := range *ei {
		if v.Height.Cmp(height) > 0 {
			index = i //find insert index
		}
	}

	evilEvidence := NewEvilEvidence(height)
	if index < len(*ei) {
		evilBlocks := (*ei)[:]
		*ei = evilBlocks[:index]
		*ei = append(*ei, evilEvidence)
		*ei = append(*ei, evilBlocks[index:]...)
	} else {
		*ei = append(*ei, evilEvidence)
	}
	return evilEvidence
}

// Remove old evil Signers when changing signers event comes from ela chain
func (signers *EvilSignersMap) RemoveOldEvilSigners(currentHeight *big.Int, rangeValue int64) error {
	if signers == nil {
		return nil
	}
	for k, v := range *signers {
		if currentHeight == nil || rangeValue <= 0 {
			break
		}
		length := len(*v)
		height := (*v)[length-1].Height
		res := new(big.Int).Sub(currentHeight, height)
		if res.Int64() > rangeValue {
			log.Info("Remove evil signers", "height to early", k.String())
			delete(*signers, k)
		}
	}
	return nil

}

// update evil signers, send evil message to ela chain return de-duplication hashes
func (signers *EvilSignersMap) UpdateEvilSigners(signer common.Address, height *big.Int, hashes []*common.Hash,
	elaHeights []uint64) (map[common.Hash]uint64, error) {
	rangeValue := blocksigner.GetBlockSignersCount()
	signers.RemoveOldEvilSigners(height, int64(rangeValue))

	evidences := &Evidences{}
	if v, ok := (*signers)[signer]; ok {
		evidences = v
	} else {
		(*signers)[signer] = evidences
		spv.SendEvilProof(signer, nil)
	}
	evidence := evidences.getEvidence(height)
	for index, hash := range hashes {
		if _, ok := evidence.BlockOnHeight[*hash]; !ok {
			log.Info("Update evil signers","signer", signer.String(), "height",
				height.String(), "blockHash", hash.String())
			evidence.BlockOnHeight[*hash] = elaHeights[index]
		}
	}
	return evidence.BlockOnHeight, nil
}

// Return whether is to much evil signers.
func (signers *EvilSignersMap) IsDanger(currentHeight *big.Int, threshold int) bool {
	if signers == nil || threshold <= 0 {
		return false
	}
	count := 0
	signersLen := blocksigner.GetBlockSignersCount()
	earliestHeight := new(big.Int).Sub(currentHeight, big.NewInt(int64(signersLen)))
	for _, v := range *signers {
		index := len(*v) - 1
		for {
			if index < 0 {
				break
			}
			if (*v)[index].Height.Cmp(currentHeight) <= 0 && (*v)[index].Height.Cmp(earliestHeight) > 0 {
				count++
			}
			index--
		}
	}
	return count >= threshold
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
	for singer, evidences := range *signers {
		for _, blockInfo := range *evidences {
			for hash, v := range blockInfo.BlockOnHeight {
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
	if length < spv.ExtraVanity + spv.ExtraSeal + spv.ExtraElaHeight {
		return 0, errors.New("header's extra length is to short")
	}
	heightBytes := head.Extra[length -  spv.ExtraSeal - spv.ExtraElaHeight : length - spv.ExtraSeal]
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
			log.Info("EvilSignerEvent Insert", "Singer", singerNew.String(), "Number:",
				headerNew.Number.Uint64(), "Hash:", hash.String())
			journal.Insert(&EvilSingerEvent{&singerNew, headerNew.Number, height, &hash})
		}
	}

	return signers.IsDanger(headerNew.Number, blocksigner.GetBlockSignersCount()*2/3)
}