package spv

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	ethCommon "github.com/elastos/Elastos.ELA.SideChain.ESC/common"

	"github.com/elastos/Elastos.ELA/common"
)

type RechargeData struct {
	TargetAddress ethCommon.Address
	TargetAmount  *big.Int
	Fee           *big.Int
	TargetData    []byte
}

type RechargeDatas []*RechargeData

func GetRechargeDataByTxhash(elaHash string) (RechargeDatas, *big.Int, error) {
	totalFee := big.NewInt(0)
	rechargeDatas := make(RechargeDatas, 0)
	if elaHash[0:2] == "0x" {
		elaHash = elaHash[2:]
	}
	transactionDBMutex.Lock()
	defer transactionDBMutex.Unlock()

	if spvTransactiondb == nil {
		return rechargeDatas, totalFee, errors.New("spvTransactiondb is not inited")
	}

	res, err := IsFailedElaTx(elaHash)
	if err != nil {
		return rechargeDatas, totalFee, err
	}
	if res {
		return rechargeDatas, totalFee, errors.New("is failed elaTx: " + elaHash)
	}

	feeValues, err := spvTransactiondb.Get([]byte(elaHash + "Fee"))
	if err != nil {
		return rechargeDatas, totalFee, err
	}

	addrss, err := spvTransactiondb.Get([]byte(elaHash + "Address"))
	if err != nil {
		return rechargeDatas, totalFee, err
	}

	outputs, err := spvTransactiondb.Get([]byte(elaHash + "Output"))
	if err != nil {
		return rechargeDatas, totalFee, err

	}

	memos, err := spvTransactiondb.Get([]byte(elaHash + "Input"))

	addrs := strings.Split(string(addrss), ",")
	fees := strings.Split(string(feeValues), ",")
	amounts := strings.Split(string(outputs), ",")
	targetMemos := strings.Split(string(memos), ",")
	fmt.Println("addrs", addrs, "fees", fees, "amounts", amounts, "targetMemos", targetMemos)
	if len(addrs) != len(fees) || len(fees) != len(amounts) || len(amounts) != len(addrs) {
		return rechargeDatas, totalFee, errors.New("recharge data error : " + elaHash)
	}

	size := len(fees)

	y := new(big.Int).SetInt64(rate)
	for i := 0; i < size; i++ {
		data := new(RechargeData)
		if !ethCommon.IsHexAddress(addrs[i]) {
			return rechargeDatas, big.NewInt(0), errors.New("error esc address" + addrs[i])
		}
		data.TargetAddress = ethCommon.HexToAddress(addrs[i])

		f, err := common.StringToFixed64(fees[i])
		if err != nil {
			return rechargeDatas, big.NewInt(0), err
		}
		fe := new(big.Int).SetInt64(f.IntValue())
		data.Fee = new(big.Int).Mul(fe, y)

		o, err := common.StringToFixed64(amounts[i])
		if err != nil {
			return rechargeDatas, big.NewInt(0), err

		}
		op := new(big.Int).SetInt64(o.IntValue())
		data.TargetAmount = new(big.Int).Mul(op, y)
		data.TargetData = []byte(targetMemos[i])
		totalFee = totalFee.Add(totalFee, data.Fee)
		rechargeDatas = append(rechargeDatas, data)
	}
	return rechargeDatas, totalFee, nil
}
