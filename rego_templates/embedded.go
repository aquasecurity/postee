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
	LOCAL_DIR  = "."
)

var (
	//go:embed *.rego
	EmbeddedFiles embed.FS
	templates     = make(map[string]string)
	templatesMu   sync.Mutex

	//go:embed common
	EmbeddedCommonFiles embed.FS
	commonTemplates     = make(map[string]string)
	commonMu            sync.Mutex
)

func GetTemplates() map[string]string {
	templatesMu.Lock()
	defer templatesMu.Unlock()
	if len(templates) != 0 {
		return templates
	}
	populateFS(EmbeddedFiles, templates, LOCAL_DIR)

	return templates
}

func GetCommon() map[string]string {
	commonMu.Lock()
	defer commonMu.Unlock()
	if len(commonTemplates) != 0 {
		return commonTemplates
	}
	populateFS(EmbeddedCommonFiles, commonTemplates, COMMON_DIR)

	return commonTemplates
}

func populateFS(files embed.FS, storage map[string]string, dirPath string) {
	dir, err := fs.ReadDir(files, dirPath)
	if err != nil {
		log.Logger.Errorf("failed to read embedded files: %s", err)
		return
	}

	for _, file := range dir {
		if file.IsDir() {
			continue
		}

		bt, err := fs.ReadFile(files, filepath.Join(dirPath, file.Name()))
		if err != nil {
			log.Logger.Errorf("failed to read embedded file '%s': %s", file.Name(), err)
			continue
		}

		storage[file.Name()] = string(bt)
	}
}
