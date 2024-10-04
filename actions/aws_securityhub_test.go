package actions

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const GoodFindings = `{
 "Findings": [
   {
     "SchemaVersion": "2018-10-08",
     "Id": "alpine:3.10 (alpine 3.10.9)/CVE-2021-36159",
     "ProductArn": "arn:aws:securityhub:eu-west-2::product/aquasecurity/aquasecurity",
     "GeneratorId": "Trivy/CVE-2021-36159",
     "AwsAccountId": "000000",
     "Types": [
       "Software and Configuration Checks/Vulnerabilities/CVE"
     ],
     "CreatedAt": "2022-08-05T22:29:18.549914-07:00",
     "UpdatedAt": "2022-08-10T22:29:18.549938-07:00",
     "Severity": {
       "Label": "CRITICAL"
     },
     "Title": "Trivy found a vulnerability to CVE-2021-36159 in container alpine:3.10 (alpine 3.10.9)",
     "Description": "libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the &#39;\\0&#39; terminator one byte too late.",
     "Remediation": {
       "Recommendation": {
         "Text": "More information on this vulnerability is provided in the hyperlink",
         "Url": "https://avd.aquasec.com/nvd/cve-2021-36159"
       }
     },
     "ProductFields": {
       "Product Name": "Trivy"
     },
     "Resources": [
       {
         "Type": "Container",
         "Id": "alpine:3.10 (alpine 3.10.9)",
         "Partition": "aws",
         "Region": "",
         "Details": {
           "Container": {
             "ImageName": "alpine:3.10 (alpine 3.10.9)"
           },
           "Other": {
             "CVE ID": "CVE-2021-36159",
             "CVE Title": "",
             "PkgName": "apk-tools",
             "Installed Package": "2.10.6-r0",
             "Patched Package": "2.10.7-r0",
             "NvdCvssScoreV3": "9.1",
             "NvdCvssVectorV3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
             "NvdCvssScoreV2": "6.4",
             "NvdCvssVectorV2": "AV:N/AC:L/Au:N/C:P/I:N/A:P"
           }
         }
       }
     ],
     "RecordState": "ACTIVE"
   },
   {
     "SchemaVersion": "2018-10-08",
     "Id": "alpine:3.10 (alpine 3.10.9)/CVE-2021-36159",
     "ProductArn": "arn:aws:securityhub:eu-west-2::product/aquasecurity/aquasecurity",
     "GeneratorId": "Trivy/CVE-2021-36159",
     "AwsAccountId": "000000",
     "Types": [
       "Software and Configuration Checks/Vulnerabilities/CVE"
     ],
     "CreatedAt": "2022-08-05T22:29:18.549914-07:00",
     "UpdatedAt": "2022-08-10T22:29:18.549938-07:00",
     "Severity": {
       "Label": "CRITICAL"
     },
     "Title": "Trivy found a vulnerability to CVE-2021-36159 in container alpine:3.10 (alpine 3.10.9)",
     "Description": "libfetch before 2021-07-26, as used in apk-tools, xbps, and other products, mishandles numeric strings for the FTP and HTTP protocols. The FTP passive mode implementation allows an out-of-bounds read because strtol is used to parse the relevant numbers into address bytes. It does not check if the line ends prematurely. If it does, the for-loop condition checks for the &#39;\\0&#39; terminator one byte too late.",
     "Remediation": {
       "Recommendation": {
         "Text": "More information on this vulnerability is provided in the hyperlink",
         "Url": "https://avd.aquasec.com/nvd/cve-2021-36159"
       }
     },
     "ProductFields": {
       "Product Name": "Trivy"
     },
     "Resources": [
       {
         "Type": "Container",
         "Id": "alpine:3.10 (alpine 3.10.9)",
         "Partition": "aws",
         "Region": "",
         "Details": {
           "Container": {
             "ImageName": "alpine:3.10 (alpine 3.10.9)"
           },
           "Other": {
             "CVE ID": "CVE-2021-36159",
             "CVE Title": "",
             "PkgName": "apk-tools",
             "Installed Package": "2.10.6-r0",
             "Patched Package": "2.10.7-r0",
             "NvdCvssScoreV3": "9.1",
             "NvdCvssVectorV3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
             "NvdCvssScoreV2": "6.4",
             "NvdCvssVectorV2": "AV:N/AC:L/Au:N/C:P/I:N/A:P"
           }
         }
       }
     ],
     "RecordState": "ACTIVE"
   }
 ]
}`

type mockAWSSHClient struct {
	_ securityHubAPI

	batchImportFindingsFunc func(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error)
}

func (mc mockAWSSHClient) BatchImportFindings(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
	if mc.batchImportFindingsFunc != nil {
		return mc.batchImportFindingsFunc(ctx, params, optFns...)
	}
	return &securityhub.BatchImportFindingsOutput{}, nil
}

func TestAWSSecurityHubClient_Send(t *testing.T) {
	t.Run("happy path, multiple findings", func(t *testing.T) {
		ac := AWSSecurityHubClient{
			client: &mockAWSSHClient{
				batchImportFindingsFunc: func(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
					t.Helper()
					assert.Equal(t, 2, len(params.Findings))

					return &securityhub.BatchImportFindingsOutput{
						SuccessCount: 2,
					}, nil
				},
			},
		}

		require.NoError(t, ac.Send(map[string]string{
			"description": GoodFindings,
		}), t.Name())
	})

	t.Run("happy path, no findings", func(t *testing.T) {
		ac := AWSSecurityHubClient{
			client: &mockAWSSHClient{
				batchImportFindingsFunc: func(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
					t.Helper()
					assert.Fail(t, "this method should not have been called")
					return nil, nil
				},
			},
		}

		require.Equal(t, "trivy AWS sent no findings to Postee, skipping sending", ac.Send(map[string]string{
			"description": `{"Findings":[]}`,
		}).Error(), t.Name())
	})

	t.Run("sad path, bad incoming event from trivy", func(t *testing.T) {
		require.Equal(t, "AWS Security Hub unmarshalling failed: invalid character 'i' looking for beginning of value", AWSSecurityHubClient{}.Send(map[string]string{
			"description": "invalid json",
		}).Error())
	})

	t.Run("sad path, aws security hub fails has an error", func(t *testing.T) {
		ac := AWSSecurityHubClient{
			client: &mockAWSSHClient{
				batchImportFindingsFunc: func(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
					t.Helper()
					return &securityhub.BatchImportFindingsOutput{}, fmt.Errorf("internal server error")
				},
			},
		}

		require.Equal(t, "upload to AWS Security Hub failed: internal server error", ac.Send(map[string]string{
			"description": GoodFindings,
		}).Error(), t.Name())
	})

	t.Run("sad path, aws security hub fails to ingest some findings", func(t *testing.T) {
		ac := AWSSecurityHubClient{
			client: &mockAWSSHClient{
				batchImportFindingsFunc: func(ctx context.Context, params *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
					t.Helper()
					return &securityhub.BatchImportFindingsOutput{
						FailedCount:  1,
						SuccessCount: 1,
						FailedFindings: []types.ImportFindingsError{
							{
								ErrorCode:    aws.String("123"),
								ErrorMessage: aws.String("bad bad"),
								Id:           aws.String("001"),
							},
						},
						ResultMetadata: middleware.Metadata{},
					}, nil
				},
			},
		}

		require.NoError(t, ac.Send(map[string]string{
			"description": GoodFindings,
		}), t.Name())
	})
}
