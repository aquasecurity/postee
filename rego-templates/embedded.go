package rego_templates

import (
	"bufio"
	"embed"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/log"
)

const (
	commonDir          = "common"
	localDir           = "."
	regoPkgDeclaration = "package"
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

func EmbeddedTemplates() map[string]string {
	templatesMu.Lock()
	defer templatesMu.Unlock()
	if len(templates) != 0 {
		return templates
	}
	populateTemplates(EmbeddedFiles, templates, localDir)

	return templates
}

func EmbeddedCommon() map[string]string {
	commonMu.Lock()
	defer commonMu.Unlock()
	if len(commonTemplates) != 0 {
		return commonTemplates
	}
	populateTemplates(EmbeddedCommonFiles, commonTemplates, commonDir)

	return commonTemplates
}

func populateTemplates(files embed.FS, storage map[string]string, dirPath string) {
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

func GetAllTemplates() []data.Template {
	var templates []data.Template
	embedded := EmbeddedTemplates()
	for name, file := range embedded {
		scanner := bufio.NewScanner(strings.NewReader(file))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, regoPkgDeclaration+" ") {
				s := strings.Split(line, " ")
				if len(s) < 2 {
					log.Logger.Warnf("package decalration is misconfigured for rego template '%s': %s", name, line)
					break
				}

				templates = append(templates, data.Template{
					Name:        strings.TrimSuffix(name, ".rego"),
					RegoPackage: s[1],
				})
				break
			}
		}
	}

	return templates
}
