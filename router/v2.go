package router

import (
	"sync"

	"github.com/aquasecurity/postee/v2/data"
)

func NewV2(requiredTemplate string) (*Router, error) {
	router := &Router{
		mutexScan:              sync.Mutex{},
		synchronous:            true,
		databaseCfgCacheSource: &data.TenantSettings{},
		version:                V2Version,
	}

	err := router.embedTemplates(requiredTemplate)
	if err != nil {
		return nil, err
	}
	return router, nil
}
