package dbservice

import (
	"data"
	"os"
	"testing"
)

var (
	AlpineImageResult = data.ScanImageInfo{
		"alpine:3.8",
		"Docker Hub",
		"sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		data.ImageAssuranceResults{
			true,
			[]data.ControlCheck{
				{"max_severity", "Default", false},
				{"trusted_base_images", "Default", true},
				{"max_score", "Default", false},
			},
		},
		data.VulnerabilitySummary{
			2, 0, 0, 2, 0,0,0,0,
		},
		data.ScanOptions{true, true},
		[]data.InfoResources{
			{
				[]data.Vulnerability{
					{"CVE-2018-20679", "", "",},
					{"CVE-2019-5747", "", "",},
				},
				data.ResourceDetails{"busybox"},
			},
		},
	}
)

func TestHandleCurrentInfo(t *testing.T) {
	var tests = []struct{
		input *data.ScanImageInfo
	}{
		{ &AlpineImageResult },
	}

	dbPathReal := DbPath
	dbBucketReal := BucketName
	defer func() {
		DbPath = dbPathReal
		BucketName = dbBucketReal
	}()

	DbPath = "test_" + dbPathReal
	BucketName = "test_" + BucketName

	for _, test := range tests {
		_, isNew, err := HandleCurrentInfo( test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("A new scan was found!\n")
		}

		_, isNew, err = HandleCurrentInfo( test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if isNew {
			t.Errorf("A old scan wasn't found!\n")
		}

		test.input.High++
		_, isNew, err = HandleCurrentInfo( test.input)
		if err != nil {
			t.Errorf("Error: %s\n", err)
		}
		if !isNew {
			t.Errorf("Updating scan was ignored!\n")
		}

	}
	os.Remove(DbPath)
}

