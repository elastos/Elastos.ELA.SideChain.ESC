package vm

import (
	"bytes"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/common"
)

type InternalCall struct {
	account common.Address
	gasCost uint64
}

func (c *Contract) OpInterCall(callAddress common.Address, gasUsed uint64) {
	for _, table := range c.internalCallTable {
		if bytes.Equal(table.account.Bytes(), callAddress.Bytes()) {
			table.gasCost += gasUsed
			return
		}
	}
	call := new(InternalCall)
	call.account = callAddress
	call.gasCost = gasUsed
	c.internalCallTable = append(c.internalCallTable, call)
	return
}

func (c *Contract) InterCallList() []*InternalCall {
	var tempList = make([]*InternalCall, 0)
	for _, data := range c.internalCallTable {
		temp := &InternalCall{account: data.account, gasCost: data.gasCost}
		tempList = append(tempList, temp)
	}
	return tempList
}
