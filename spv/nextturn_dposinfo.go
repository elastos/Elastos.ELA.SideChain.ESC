package spv

import (
	"errors"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/chainbridge-core/engine"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

	spv "github.com/elastos/Elastos.ELA.SPV/interface"

	"github.com/elastos/Elastos.ELA/core/types/payload"
)

type NextTurnDPOSInfo struct {
	*payload.NextTurnDPOSInfo

	SuperNodePublicKey []byte
}

var (
	nextTurnDposInfo *NextTurnDPOSInfo

	superNodePublicKey []byte
)

func GetTotalProducersCount() int {
	if nextTurnDposInfo == nil {
		return 0
	}
	count, err := SafeAdd(len(nextTurnDposInfo.CRPublicKeys), len(nextTurnDposInfo.DPOSPublicKeys))
	if len(nextTurnDposInfo.SuperNodePublicKey) > 0 && err == nil {
		count, err = SafeAdd(count, 1)
	}
	if err != nil {
		log.Error("SafeAdd error", "error", err)
		return 0
	}
	return count
}

func SpvIsWorkingHeight() bool {
	if nextTurnDposInfo != nil {
		return SpvService.GetBlockListener().BlockHeight() > nextTurnDposInfo.WorkingHeight
	}
	return false
}

func MainChainIsPowMode() bool {
	return consensusMode == spv.POW
}

func GetProducers(elaHeight uint64) ([][]byte, int, error) {
	producers := make([][]byte, 0)
	totalCount := 0
	if SpvService == nil {
		return producers, totalCount,  errors.New("spv is not start")
	}
	if GetCurrentConsensusMode() == spv.POW {
		return producers, totalCount, nil
	}
	crcArbiters, normalArbitrs, err := SpvService.GetArbiters(uint32(elaHeight))
	if err != nil {
		return producers, totalCount, err
	}
	if IsOnlyCRConsensus {
		normalArbitrs = make([][]byte, 0)
	}
	isLayer2Started := false
	if engine, ok := PbftEngine.(engine.ESCEngine); ok {
		isLayer2Started = engine.Layer2Started()
		if isLayer2Started {
			producers = append(producers, superNodePublicKey)
		}
	}
	for _, arbiter := range crcArbiters {
		if len(arbiter) > 0 {
			producers = append(producers, arbiter)
		}
	}
	for _, arbiter := range normalArbitrs {
		if len(arbiter) > 0 {
			producers = append(producers, arbiter)
		}
	}
	totalCount, err = SafeAdd(len(crcArbiters), len(normalArbitrs))
	if isLayer2Started && err == nil {
		totalCount, err =  SafeAdd(totalCount, 1)
	}
	if err != nil {
		return nil, totalCount, err
	}
	return producers, totalCount, nil
}

func GetSpvHeight() uint64  {
	if SpvService != nil && SpvService.GetBlockListener() != nil {
		header, err := SpvService.HeaderStore().GetBest()
		if err != nil {
			log.Error("SpvService getBest error", "error", err)
			return uint64(SpvService.GetBlockListener().BlockHeight())
		}
		return uint64(header.Height)
	}
	return 0
}

func GetWorkingHeight() uint32  {
	if nextTurnDposInfo != nil {
		return nextTurnDposInfo.WorkingHeight
	}
	return 0
}

func GetSpvService() *Service  {
	return SpvService
}