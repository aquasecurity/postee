package actions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

type DependencyTrackAction struct {
	Name   string
	Url    string
	APIKey string
}

func (dta *DependencyTrackAction) GetName() string {
	return dta.Name
}

func (dta *DependencyTrackAction) Init() error {
	log.Printf("Starting Dependency Track action %s, for sending to %s", dta.Name, dta.Url)
	return nil
}

func (dta *DependencyTrackAction) Send(content map[string]string) error {
	project, ok := content["title"]
	if !ok && project == "" {
		return fmt.Errorf("title key not found")
	}

	projectAndVersion := strings.SplitN(project, ":", 2)
	if len(projectAndVersion) != 2 {
		return fmt.Errorf("title key has wrong format")
	}

	bom, err := json.Marshal(json.RawMessage(content["description"]))
	if err != nil {
		return fmt.Errorf("description key has wrong format: %w", err)
	}

	client, err := dtrack.NewClient(dta.Url, dtrack.WithAPIKey(dta.APIKey))
	if err != nil {
		return fmt.Errorf("failed to create dependency track client: %w", err)
	}

	ctx := context.Background()

	_, err = client.BOM.Upload(ctx, dtrack.BOMUploadRequest{
		ProjectName:    projectAndVersion[0],
		ProjectVersion: projectAndVersion[1],
		AutoCreate:     true,
		BOM:            base64.StdEncoding.EncodeToString(bom),
	})

	if err != nil {
		return fmt.Errorf("failed to upload BOM: %w", err)
	}

	return nil
}

func (dta *DependencyTrackAction) Terminate() error {
	log.Printf("Dependency Track action %s terminated.", dta.Name)
	return nil
}

func (dta *DependencyTrackAction) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.HtmlProvider)
}
