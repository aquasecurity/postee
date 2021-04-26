package alertmgr

type TenantSettings struct {
	Name            string           `json:"name"`
	AquaServer      string           `json:"AquaServer"`
	DBMaxSize       int              `json:"Max_DB_Size"`
	DBRemoveOldData int              `json:"Delete_Old_Data"`
	DBTestInterval  int              `json:"DbVerifyInterval"`
	Outputs         []PluginSettings `json:"outputs"`
	InputRules      []InputRoutes    `json:"Rules"`
	Templates       []Template       `json:"templates"`
}