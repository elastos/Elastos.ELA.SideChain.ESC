package bridgelog

import "github.com/elastos/Elastos.ELA.SideChain.ESC/log"

func Info(msg string, ctx ...interface{}) {
	log.Info("[chainbridge info]", "", msg, "", ctx)
}

func Error(msg string, ctx ...interface{}) {
	log.Error("[chainbridge error]", "", msg, "", ctx)
}

func Warn(msg string, ctx ...interface{}) {
	log.Error("[chainbridge warn]", "", msg, "", ctx)
}