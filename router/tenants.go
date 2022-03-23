package router

import (
	"github.com/aquasecurity/postee/v2/routes"
)

type TenantSettings struct {
	AquaServer      string              `json:"aqua-server,omitempty"`
	DBMaxSize       string              `json:"max-db-size,omitempty"`
	DBRemoveOldData int                 `json:"delete-old-data,omitempty"`
	DBTestInterval  int                 `json:"db-verify-interval,omitempty"`
	Outputs         []OutputSettings    `json:"outputs"`
	InputRoutes     []routes.InputRoute `json:"routes"`
	Templates       []Template          `json:"templates"`
}
