package router

import (
	"sync"

	"github.com/aquasecurity/postee/v2/data"
)

func NewV2() (*Router, error) {
	router := &Router{
		mutexScan:              sync.Mutex{},
		synchronous:            true,
		databaseCfgCacheSource: &data.TenantSettings{},
		version:                V2Version,
	}

	err := router.embedTemplates()
	if err != nil {
		return nil, err
	}
	return router, nil
}
