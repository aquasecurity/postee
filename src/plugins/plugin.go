package plugins

import (
	"fmt"
	"layout"
	"log"
	"settings"
	"strings"
)

const (
	ApplicationScopeOwner = "<%application_scope_owner%>"
)

func getHandledRecipients(recipients []string, content *map[string]string, pluginName string) []string {
	var result []string
	for _, r := range recipients {
		if r == ApplicationScopeOwner {
			owners, err := getAppScopeOwners(content)
			if err != nil {
				log.Printf("get application scope owners error for %q: %v", pluginName, err)
				continue
			}
			result = append(result, owners...)
		} else {
			result = append(result, r)
		}
	}
	return result
}

func getAppScopeOwners(content *map[string]string) ([]string, error) {
	ownersIn, ok := (*content)["owners"]
	if !ok {
		return nil, fmt.Errorf("recipients field contains %q, but received a webhook without this data",
			ApplicationScopeOwner)
	}
	return strings.Split(ownersIn, ";"), nil
}

type Plugin interface {
	Init() error
	Send(map[string]string) error
	Terminate() error
	GetLayoutProvider() layout.LayoutProvider
	GetSettings() *settings.Settings
}
