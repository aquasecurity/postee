package router

import (
	"bytes"
	"io/ioutil"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/log"
	"github.com/ghodss/yaml"
)

const (
	v1Marker  = "- type: common"
	v1Warning = `


@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

  Options supported only in Postee V1 are found in %s. Please make sure app is configured correctly!
  See https://github.com/aquasecurity/postee/blob/main/README.md for the details.

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


`
)

func Parsev2cfg(cfgpath string) (*data.TenantSettings, error) {
	b, err := ioutil.ReadFile(cfgpath)
	if err != nil {
		return nil, err
	}

	checkV1Cfg(b, cfgpath)

	tenant := &data.TenantSettings{}
	err = yaml.Unmarshal(b, tenant)

	if err != nil {
		return nil, err
	}

	return tenant, nil

}
func checkV1Cfg(data []byte, cfgpath string) {
	if bytes.Index(data, []byte(v1Marker)) > -1 {
		log.Logger.Warnf(v1Warning, cfgpath)
	}
}
