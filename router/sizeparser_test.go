package router

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
)

func TestParseSize(t *testing.T) {
	tests := []struct {
		name       string
		sizeString string
		wantSize   int
	}{
		{
			name:       "happy path(empty string is used)",
			sizeString: "",
			wantSize:   0,
		},
		{
			name:       "happy path(suffix 'b' is used)",
			sizeString: "1b",
			wantSize:   1,
		},
		{
			name:       "happy path(suffix 'kb' is used)",
			sizeString: "2kb",
			wantSize:   2 * KB,
		},
		{
			name:       "happy path(suffix 'Mb' is used)",
			sizeString: "3Mb",
			wantSize:   3 * MB,
		},
		{
			name:       "happy path(suffix 'GB' is used)",
			sizeString: "4GB",
			wantSize:   4 * GB,
		},
		{
			name:       "happy path(suffix ' b' is used)",
			sizeString: "5 b",
			wantSize:   5,
		},
		{
			name:       "happy path(suffix is not used)",
			sizeString: "6",
			wantSize:   6,
		},
		{
			name:       "sad path(suffix 'tb' is used)",
			sizeString: "7TB",
			wantSize:   0,
		},
		{
			name:       "sad path(float value is used)",
			sizeString: "8.8",
			wantSize:   0,
		},
		{
			name:       "sad path(value more than MaxInt)",
			sizeString: fmt.Sprintf("%d1", math.MaxInt),
			wantSize:   0,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			size := parseSize(test.sizeString)

			assert.EqualValues(t, test.wantSize, size)
		})
	}
}
