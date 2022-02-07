package rego_templates

import (
	"embed"
	"io/fs"
	"path/filepath"
	"sync"

	"github.com/aquasecurity/postee/v2/log"
)

const (
	COMMON_DIR = "common"
)

var (
	//go:embed *.rego
	EmbeddedFiles embed.FS
	templates     map[string]string

	//go:embed common
	EmbeddedCommonFiles embed.FS
	commonTemplates     = make(map[string]string)
	commonMu            sync.RWMutex
)

func GetCommon() map[string]string {
	commonMu.Lock()
	defer commonMu.Unlock()
	if len(commonTemplates) != 0 {
		return commonTemplates
	}
	populateCommon()

	return commonTemplates
}

func populateCommon() {
	dir, err := fs.ReadDir(EmbeddedCommonFiles, COMMON_DIR)
	if err != nil {
		log.Logger.Errorf("failed to read embedded common files: %s", err)
		return
	}

	for _, file := range dir {
		if file.IsDir() {
			continue
		}

		bt, err := fs.ReadFile(EmbeddedCommonFiles, filepath.Join(COMMON_DIR, file.Name()))
		if err != nil {
			log.Logger.Errorf("failed to read embedded common file '%s': %s", file.Name(), err)
			continue
		}

		commonTemplates[file.Name()] = string(bt)
	}
}
