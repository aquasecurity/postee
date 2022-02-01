package router

import (
	"bytes"
	"io/ioutil"
	"log"

	"github.com/aquasecurity/postee/data"
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
		log.Printf("Failed to open file %s, %s", cfgpath, err)
		return nil, err
	}

	checkV1Cfg(b, cfgpath)

	tenant := &data.TenantSettings{}
	err = yaml.Unmarshal(b, tenant)

	if err != nil {
		log.Printf("Failed yaml.Unmarshal, %s", err)
		return nil, err
	}

	return tenant, nil

}
func checkV1Cfg(data []byte, cfgpath string) {
	if bytes.Index(data, []byte(v1Marker)) > -1 {
		log.Printf(v1Warning, cfgpath)
	}
}
