package msgservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCalculateExpired(t *testing.T) {
	tests := []struct {
		timeout int
	}{
		{
			0,
		},
		{
			1,
		},
		{
			2,
		},
		{
			100,
		},
	}

	for _, test := range tests {
		r := calculateExpired(test.timeout)

		if test.timeout == 0 {
			assert.Nil(t, r)
		} else {
			n := time.Now()
			diff := r.Sub(n)
			assert.GreaterOrEqual(t, float64(test.timeout), diff.Seconds())
		}
	}
}
