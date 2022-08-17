package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

type securityHubAPI interface {
	BatchImportFindings(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error)
}

type Finding struct {
	SchemaVersion string   `json:"SchemaVersion,omitempty"`
	ID            string   `json:"Id,omitempty"`
	ProductArn    string   `json:"ProductArn,omitempty"`
	GeneratorID   string   `json:"GeneratorId,omitempty"`
	AwsAccountID  string   `json:"AwsAccountId,omitempty"`
	Types         []string `json:"Types,omitempty"`
	CreatedAt     string   `json:"CreatedAt,omitempty"`
	UpdatedAt     string   `json:"UpdatedAt,omitempty"`
	Severity      struct {
		Label string `json:"Label,omitempty"`
	} `json:"Severity,omitempty"`
	Title       string `json:"Title,omitempty"`
	Description string `json:"Description,omitempty"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text,omitempty"`
			URL  string `json:"Url,omitempty"`
		} `json:"Recommendation,omitempty"`
	} `json:"Remediation,omitempty"`
	ProductFields struct {
		ProductName string `json:"Product Name,omitempty"`
	} `json:"ProductFields,omitempty"`
	Resources []struct {
		Type      string `json:"Type,omitempty"`
		ID        string `json:"Id,omitempty"`
		Partition string `json:"Partition,omitempty"`
		Region    string `json:"Region,omitempty"`
		Details   struct {
			Container struct {
				ImageName string `json:"ImageName,omitempty"`
			} `json:"Container,omitempty"`
			Other struct {
				CVEID            string `json:"CVE ID,omitempty"`
				CVETitle         string `json:"CVE Title,omitempty"`
				PkgName          string `json:"PkgName,omitempty"`
				InstalledPackage string `json:"Installed Package,omitempty"`
				PatchedPackage   string `json:"Patched Package,omitempty"`
				NvdCvssScoreV3   string `json:"NvdCvssScoreV3,omitempty"`
				NvdCvssVectorV3  string `json:"NvdCvssVectorV3,omitempty"`
				NvdCvssScoreV2   string `json:"NvdCvssScoreV2,omitempty"`
				NvdCvssVectorV2  string `json:"NvdCvssVectorV2,omitempty"`
			} `json:"Other,omitempty"`
		} `json:"Details,omitempty"`
	} `json:"Resources,omitempty"`
	RecordState string `json:"RecordState,omitempty"`
}

type Report struct {
	Findings []Finding
}

type AWSSecurityHubClient struct {
	client securityHubAPI

	Name string
}

func (sh AWSSecurityHubClient) GetName() string {
	return sh.Name
}

func (sh *AWSSecurityHubClient) Init() error {
	// Load the Shared AWS Configuration (~/.aws/config)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	sh.client = securityhub.NewFromConfig(cfg)
	if sh.client == nil {
		return fmt.Errorf("failed to create AWS Security Hub client")
	}

	return nil
}

func (sh AWSSecurityHubClient) Send(m map[string]string) error {
	var r Report
	if err := json.Unmarshal([]byte(m["description"]), &r); err != nil {
		return fmt.Errorf("AWS Security Hub unmarshalling failed: %w", err)
	}

	if len(r.Findings) <= 0 {
		return fmt.Errorf("trivy AWS sent no findings to Postee, skipping sending")
	}

	var awsfindings []types.AwsSecurityFinding
	for _, f := range r.Findings {
		af := types.AwsSecurityFinding{
			AwsAccountId:  aws.String(f.AwsAccountID),
			CreatedAt:     aws.String(f.CreatedAt),
			Description:   aws.String(f.Description),
			GeneratorId:   aws.String(f.GeneratorID),
			Id:            aws.String(f.ID),
			ProductArn:    aws.String(f.ProductArn),
			SchemaVersion: aws.String(f.SchemaVersion),
			Title:         aws.String(f.Title),
			UpdatedAt:     aws.String(f.UpdatedAt),
			Types:         f.Types,
		}

		af.Resources = append(af.Resources, []types.Resource{
			{
				Id:   aws.String(f.ID),
				Type: aws.String(strings.Join(f.Types, " ")),
			},
		}...)

		af.Remediation = &types.Remediation{
			Recommendation: &types.Recommendation{
				Text: aws.String(f.Remediation.Recommendation.Text),
				Url:  aws.String(f.Remediation.Recommendation.URL),
			},
		}

		af.Severity = &types.Severity{
			Label: types.SeverityLabel(f.Severity.Label),
		}

		awsfindings = append(awsfindings, af)
	}

	var successCount, failedCount int
	awsFindingChunks := chunkBy(awsfindings, 100)
	log.Printf("sending %d findings in %d chunk(s) to AWS Security Hub", len(awsfindings), len(awsFindingChunks))
	for _, awsfindingChunk := range awsFindingChunks {
		output, err := sh.client.BatchImportFindings(context.TODO(), &securityhub.BatchImportFindingsInput{
			Findings: awsfindingChunk,
		})
		if err != nil {
			return fmt.Errorf("upload to AWS Security Hub failed: %w", err)
		}

		if len(output.FailedFindings) > 0 {
			failedCount += len(output.FailedFindings)
			log.Printf("%d findings failed to be reported...", len(output.FailedFindings))
			for _, ff := range output.FailedFindings {
				log.Printf("Failed finding details: ID: %s , ErrorCode: %s, ErrorMessage: %s\n", *ff.Id, *ff.ErrorCode, *ff.ErrorMessage)
			}
		}
		successCount += int(output.SuccessCount)
	}

	log.Printf("successfully sent: %d findings to AWS Security Hub", successCount)
	return nil
}

func (sh AWSSecurityHubClient) Terminate() error {
	return nil
}

func (sh AWSSecurityHubClient) GetLayoutProvider() layout.LayoutProvider {
	// Todo: This is MOCK. Because Formatting isn't need for Webhook
	// todo: The App should work with `return nil`
	return new(formatting.HtmlProvider)
}

func chunkBy[T any](items []T, chunkSize int) (chunks [][]T) {
	for chunkSize < len(items) {
		items, chunks = items[chunkSize:], append(chunks, items[0:chunkSize:chunkSize])
	}
	return append(chunks, items)
}
