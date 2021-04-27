package alertmgr

import (
	"github.com/aquasecurity/postee/routes"
	"github.com/aquasecurity/postee/templateservice"
)

type TenantSettings struct {
	AquaServer      string                     `json:"AquaServer"`
	DBMaxSize       int                        `json:"Max_DB_Size"`
	DBRemoveOldData int                        `json:"Delete_Old_Data"`
	DBTestInterval  int                        `json:"DbVerifyInterval"`
	Outputs         []PluginSettings           `json:"outputs"`
	InputRoutes     []routes.InputRoutes       `json:"routes"`
	Templates       []templateservice.Template `json:"templates"`
}
