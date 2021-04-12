package cfgdata

import (
	"encoding/json"
	"github.com/ghodss/yaml"
	"io/ioutil"
)

func ReadAll(cfgFile string) ([]byte, error)  {
	d, err := ioutil.ReadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	settings := []PluginSettings{}
	yaml.Unmarshal(d, &settings)
	b, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	return b, nil
}