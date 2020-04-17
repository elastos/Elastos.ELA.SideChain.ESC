package dpos

import (
	"github.com/elastos/Elastos.ELA/account"
	daccount "github.com/elastos/Elastos.ELA/dpos/account"
)

func GetDposAccount(keystorePath string, password []byte) (daccount.Account, error) {
	client, err := account.Open(keystorePath, password)
	if err != nil {
		return nil, err
	}
	return daccount.New(client.GetMainAccount()), nil
}