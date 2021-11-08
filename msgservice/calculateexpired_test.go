package msgservice

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCalculateExpired(t *testing.T) {
	timeouts := []int{0, 1, 2, 100}

	for _, timeout := range timeouts {
		r := calculateExpired(timeout)

		if timeout == 0 {
			assert.Nil(t, r)
		} else {
			n := time.Now()
			diff := r.Sub(n)
			assert.GreaterOrEqual(t, float64(timeout), diff.Seconds())
		}
	}
}
