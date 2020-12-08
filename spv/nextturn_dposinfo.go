package spv

import (
	"github.com/elastos/Elastos.ELA.SideChain.ETH/log"
	"github.com/elastos/Elastos.ELA/core/types/payload"
)

var (
	nextTurnDposInfo *payload.NextTurnDPOSInfo
)

func GetTotalProducersCount() int {
	if nextTurnDposInfo == nil {
		return 0
	}
	count := len(nextTurnDposInfo.CRPublickeys) + len(nextTurnDposInfo.DPOSPublicKeys)
	return count
}

func SpvIsWorkingHeight() bool {
	if nextTurnDposInfo != nil {
		return SpvService.GetBlockListener().BlockHeight() >= nextTurnDposInfo.WorkingHeight
	}
	return false
}

func GetArbitersCount(elaHeight uint64) int {
	crcArbiters, normalArbitrs, err := SpvService.GetArbiters(uint32(elaHeight))
	if err != nil {
		log.Error("GetArbiters error", "error", err.Error())
		return 0
	}
	return len(crcArbiters) + len(normalArbitrs)
}

func GetProducers(elaHeight uint64) ([][]byte, int) {
	producers := make([][]byte, 0)
	totalCount := 0
	crcArbiters, normalArbitrs, err := SpvService.GetArbiters(uint32(elaHeight))
	if err != nil {
		log.Error("GetProducers error", "error", err.Error())
		return producers, totalCount
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
	totalCount = len(crcArbiters) + len(normalArbitrs)
	return producers, totalCount
}

func GetSpvHeight() uint64  {
	if SpvService != nil && SpvService.GetBlockListener() != nil {
		return uint64(SpvService.GetBlockListener().BlockHeight())
	}
	return 0
}

func GetWorkingHeight() uint32  {
	if nextTurnDposInfo != nil {
		return nextTurnDposInfo.WorkingHeight
	}
	return 0
}