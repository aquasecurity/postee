package outputs

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"
)

const (
	ApplicationScopeOwner = "<%application_scope_owner%>"

	EventCategoryAttribute = "event_category"
	CategoryIncident       = "incident"
	CategoryScanResult     = "scan_result"

	EmptyID = ""
)

type Output interface {
	GetType() string
	GetName() string
	Init() error
	Send(map[string]string) (data.OutputResponse, error)
	Terminate() error
	GetLayoutProvider() layout.LayoutProvider
	CloneSettings() *data.OutputSettings //TODO shouldn't return reference
}

func getHandledRecipients(recipients []string, content *map[string]string, outputName string) []string {
	var result []string
	for _, r := range recipients {
		if r == ApplicationScopeOwner {
			owners, err := getAppScopeOwners(content)
			if err != nil {
				log.Logger.Errorf("get application scope owners error for %q: %v", outputName, err)
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
