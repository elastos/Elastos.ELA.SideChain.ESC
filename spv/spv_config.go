package spv

import (
	"bytes"
	"encoding/json"
	spv "github.com/elastos/Elastos.ELA.SPV/interface"
	"github.com/elastos/Elastos.ELA.SideChain.ESC/log"
	"github.com/elastos/Elastos.ELA/common/config"
	"io/ioutil"
	"reflect"
)

const (
	DefaultConfigFilename = "./spvconfig.json"
	Foundation            = "FoundationAddress"
	CRCAddress            = "CRCAddress"
	GenesisBlock          = "GenesisBlock"
	PowLimit              = "PowLimit"
)

var PreferConfig PreferParams

type PreferParams struct {
	Config config.Configuration `json:"Configuration"`
}

func init() {
	PreferConfig = PreferParams{Config: config.Configuration{MaxLogsSize: 0, MaxPerLogSize: 0, PrintLevel: 1}}
	file, err := ioutil.ReadFile(DefaultConfigFilename)
	if err != nil {
		log.Warn("Read Spv_config file  error", "error", err)
		return
	}
	// Remove the UTF-8 Byte Ord er Mark
	file = bytes.TrimPrefix(file, []byte("\xef\xbb\xbf"))
	err = json.Unmarshal(file, &PreferConfig)
	if err != nil {
		log.Warn("Unmarshal Spv_config file json error", "error", err)
	}
}

func ResetConfigWithReflect(params *config.Configuration, spvConfig *spv.Config) {
	paramsType := reflect.TypeOf(*params)
	paramsValue := reflect.ValueOf(params).Elem()
	configType := reflect.TypeOf(PreferConfig.Config)
	configValue := reflect.ValueOf(PreferConfig.Config)
	spvType := reflect.TypeOf(*spvConfig)
	spvValue := reflect.ValueOf(spvConfig).Elem()
	var destField reflect.Value
	for i := 0; i < configType.NumField(); i++ {
		name := configType.Field(i).Name
		value := configValue.Field(i)
		field := configType.Field(i)
		if _, ok := paramsType.FieldByName(name); ok {
			destField = paramsValue.FieldByName(name)
		} else if _, ok := spvType.FieldByName(name); ok {
			destField = spvValue.FieldByName(name)
		} else {
			continue
		}
		switch field.Type.Kind() {
		case reflect.Bool:
			destField.SetBool(value.Bool())
		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v := value.Int()
			if v > 0 {
				destField.SetInt(v)
			}
		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v := value.Uint()
			if v > 0 {
				destField.SetUint(v)
			}
		case reflect.Float32, reflect.Float64:
			v := value.Float()
			if v > 0.0 {
				destField.SetFloat(v)
			}
		case reflect.String:
			v := value.String()
			if len(v) == 0 {
				break
			}
			//if name == Foundation || name == CRCAddress {
			//	t, err := common.Uint168FromAddress(v)
			//	if err == nil {
			//		arrayValue := reflect.ValueOf(t).Elem()
			//		destField.Set(arrayValue)
			//		if name == Foundation {
			//			block := core.GenesisBlock(*t)
			//			if _, ok := paramsType.FieldByName(GenesisBlock); ok {
			//				blockValue := reflect.ValueOf(block)
			//				destField = paramsValue.FieldByName(GenesisBlock)
			//				destField.Set(blockValue)
			//			}
			//		}
			//
			//	}
			//	break
			//}
			destField.Set(value)
		case reflect.Slice:
			if !value.IsNil() {
				destField.Set(value)
			}
		case reflect.Ptr:
			if !value.IsNil() {
				destField.Set(value)
			}
		}

	}
}
