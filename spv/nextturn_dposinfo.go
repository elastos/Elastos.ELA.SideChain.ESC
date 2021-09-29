package spv

import (
	"errors"

	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"

	spv "github.com/elastos/Elastos.ELA.SPV/interface"

	"github.com/elastos/Elastos.ELA/core/types/payload"
)

var (
	nextTurnDposInfo *payload.NextTurnDPOSInfo
)

func GetTotalProducersCount() int {
	if nextTurnDposInfo == nil {
		return 0
	}
	count, err := SafeAdd(len(nextTurnDposInfo.CRPublicKeys), len(nextTurnDposInfo.DPOSPublicKeys))
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
	crcArbiters, normalArbitrs, err := SpvService.GetArbiters(uint32(elaHeight))
	if err != nil {
		return producers, totalCount, err
	}
	if IsOnlyCRConsensus {
		normalArbitrs = make([][]byte, 0)
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
	if err != nil {
		return nil, totalCount, err
	}
	return producers, totalCount, nil
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