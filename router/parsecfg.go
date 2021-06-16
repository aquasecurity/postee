package router

import (
	"io/ioutil"
	"log"

	"github.com/ghodss/yaml"
)

func Parsev2cfg(cfgpath string) (*TenantSettings, error) {
	data, err := ioutil.ReadFile(cfgpath)
	if err != nil {
		log.Printf("Failed to open file %s, %s", cfgpath, err)
		return nil, err
	}

	tenant := &TenantSettings{}
	err = yaml.Unmarshal(data, tenant)

	if err != nil {
		log.Printf("Failed yaml.Unmarshal, %s", err)
		return nil, err
	}

	return tenant, nil

}
