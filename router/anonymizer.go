package router

import "reflect"

func anonymizeSettings(settings *ActionSettings) *ActionSettings {
	fieldsToAnonymize := [...]string{
		"User",
		"Password",
		"Url",
		"InstanceName",
	}
	copyToAnonymize := *settings

	for _, key := range fieldsToAnonymize {

		r := reflect.ValueOf(&copyToAnonymize)
		v := reflect.Indirect(r).FieldByName(key)
		prop := v.String()

		if prop != "" {
			v.SetString(AnonymizeReplacement)
		}
	}

	return &copyToAnonymize
}
