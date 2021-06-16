package router

import (
	"github.com/aquasecurity/postee/routes"
)

type TenantSettings struct {
	AquaServer      string              `json:"AquaServer,omitempty"`
	DBMaxSize       int                 `json:"Max_DB_Size,omitempty"`
	DBRemoveOldData int                 `json:"Delete_Old_Data,omitempty"`
	DBTestInterval  int                 `json:"DbVerifyInterval,omitempty"`
	Outputs         []OutputSettings    `json:"outputs"`
	InputRoutes     []routes.InputRoute `json:"routes"`
	Templates       []Template          `json:"templates"`
}
