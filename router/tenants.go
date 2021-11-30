package router

import (
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/routes"
)

type TenantSettings struct {
	Name        string               `json:"name,omitempty"`
	AquaServer  string               `json:"aqua-server,omitempty"`
	DbSettings  dbservice.DbSettings `json:"dbsettings"`
	Outputs     []OutputSettings     `json:"outputs"`
	InputRoutes []routes.InputRoute  `json:"routes"`
	Templates   []Template           `json:"templates"`
}
