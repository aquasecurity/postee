package dbservice

import (
	"encoding/json"
	"github.com/aquasecurity/postee/data"
	"os"
	"testing"
)

var (
	AlpineImageResult = data.ScanImageInfo{
		Image:          "alpine:3.8",
		Registry:       "Docker Hub",
		Digest:         "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		PreviousDigest: "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		ImageAssuranceResults: data.ImageAssuranceResults{
			true,
			[]data.ControlCheck{
				{"max_severity", "Default", false},
				{"trusted_base_images", "Default", true},
				{"max_score", "Default", false},
			},
		},
		VulnerabilitySummary: data.VulnerabilitySummary{
			2, 0, 0, 2, 0, 0, 0, 0,
		},
		ScanOptions: data.ScanOptions{true, true},
		Resources: []data.InfoResources{
			{
				[]data.Vulnerability{
					{"CVE-2018-20679", "", "", "medium"},
					{"CVE-2019-5747", "", "", "medium"},
				},
				data.ResourceDetails{"busybox", "1.28.4-r3"},
			},
		},
	}
)

func TestHandleCurrentInfo(t *testing.T) {
	var tests = []struct {
		input *data.ScanImageInfo
	}{
		{&AlpineImageResult},
	}

	dbPathReal := DbPath
	defer func() {
		DbPath = dbPathReal
	}()
	DbPath = "test_webhooks.db"

	for _, test := range tests {

		// Handling of first scan
		_, isNew, err := HandleCurrentInfo(test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("A first scan was found!\n")
		}

		// Handling of second scan with the same data
		_, isNew, err = HandleCurrentInfo(test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if isNew {
			t.Errorf("A old scan wasn't found!\n")
		}

		// Change number of High vulnerabilities and handling it
		test.input.High++
		_, isNew, err = HandleCurrentInfo(test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("Updating scan was ignored!\n")
		}

		// image scan with same name and registry, but different digest than previous scan.
		// get bytes of Base Scan
		testScanBytes, err := json.Marshal(test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		t.Log("Base scan:", string(testScanBytes))
		// Set current scan as previous for a next scan, and change digest inside a new scan
		test.input.PreviousDigest, test.input.Digest = test.input.Digest, "sha256:manual_digest"

		prevScanBytesFromDb, isNew, err := HandleCurrentInfo(test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		t.Log("Prev scan:", string(prevScanBytesFromDb))

		if !isNew {
			t.Errorf("Scan with updated digest was ignored!\n")
		}

		// PrevScan must be equals BaseScan
		if len(testScanBytes) != len(prevScanBytesFromDb) {
			t.Errorf("Prev scan is wrong!\nResult:%s\nWaiting:%s\n", prevScanBytesFromDb, testScanBytes)
		} else {
			for i := range prevScanBytesFromDb {
				if testScanBytes[i] != prevScanBytesFromDb[i] {
					t.Errorf("Prev scan is wrong!\nResult:%s\nWaiting:%s\n",
						string(prevScanBytesFromDb), string(testScanBytes))
					break
				}
			}
		}
	}
	os.Remove(DbPath)
}
