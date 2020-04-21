package main

import (
	"fmt"
	"github.com/elastos/Elastos.ELA/common"
)

func main()  {

	//crypto.GenerateKeyPair()
	prv, _ := common.HexStringToBytes("2cc0e9e53b8bd8dd037cf16e329b89f5294fca2ea3f8bd23c986e501949af684")
	fmt.Println(prv)
	//fmt.Println(common.BytesToHexString(prv))

	//pubbytes, _ := pub.EncodePoint(true)
	//fmt.Println(common.BytesToHexString(pubbytes))
}