package spv

import (
	"errors"
	"github.com/elastos/Elastos.ELA/common"
)

func SafeAdd(a int, b int) (int, error) {
	c := a + b
	if c < a {
		return 0, errors.New("safe add overflow")
	}
	return c, nil
}

func SafeMinus(a int, b int) (int, error) {
	if a < b {
		return 0, errors.New("SafeMinus a < b")
	}
	return a - b, nil
}


func SafeFixed64Minus(a common.Fixed64, b common.Fixed64) (common.Fixed64, error) {
	if a < b {
		return 0, errors.New("SafeFixed64Minus a < b")
	}
	return a - b, nil
}

func SafeUInt64Minus(a uint64, b uint64) (uint64, error) {
	if a < b {
		return 0, errors.New("SafeUInt64Minus a < b")
	}
	return a - b, nil
}