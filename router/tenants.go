package router

import (
	"github.com/aquasecurity/postee/v2/routes"
)

type TenantSettings struct {
	AquaServer      string              `json:"aqua-server,omitempty"`
	DBMaxSize       string              `json:"max-db-size,omitempty"`
	DBRemoveOldData int                 `json:"delete-old-data,omitempty"`
	DBTestInterval  int                 `json:"db-verify-interval,omitempty"`
	Actions         []ActionSettings    `json:"actions,omitempty"`
	InputRoutes     []routes.InputRoute `json:"routes,omitempty"`
	Templates       []Template          `json:"templates,omitempty"`
	Rules           []Rule              `json:"rules,omitempty"`
}
