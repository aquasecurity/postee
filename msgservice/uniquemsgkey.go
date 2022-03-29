package msgservice

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	propSep = "."
)

func GetMessageUniqueId(in map[string]interface{}, props []string) string {
	values := make([]string, 0)
	for _, prop := range props {
		parts := strings.Split(prop, propSep)
		v := getSingleValue(in, parts)
		if v != "" {
			values = append(values, v)
		}
	}
	return strings.Join(values, "-")
}

func getSingleValue(o interface{}, parts []string) string {
	in, ok := o.(map[string]interface{})

	if !ok {
		return ""
	}

	if len(parts) == 1 {
		v, ok := in[parts[0]]
		if ok {
			return fmt.Sprintf("%v", v)
		}
	} else {
		part := parts[0]
		v, ok := in[part]
		if ok {
			switch x := v.(type) {
			case map[string]interface{}:
				return getSingleValue(x, parts[1:])
			case []map[string]interface{}:
				if len(x) > 0 {
					return getSingleValue(x[0], parts[1:]) //re-iterate with first element
				}
			case string:
				js, ok := isJSON(x)
				if ok {
					return getSingleValue(js, parts[1:])
				}

			}
		}

	}
	return ""
}

func isJSON(s string) (map[string]interface{}, bool) {
	js := make(map[string]interface{})
	if json.Unmarshal([]byte(s), &js) != nil {
		return js, false
	}
	return js, true
}
