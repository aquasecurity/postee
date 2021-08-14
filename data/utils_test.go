package data

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClearField(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"test\r", "test"},
		{"test\n", "test"},
		{"the\xFF \xFDtest", "the test"},
	}

	for _, test := range tests {
		if got := ClearField(test.in); got != test.out {
			t.Errorf("ClearField(%q) == %q, want %q", test.in, got, test.out)
		}
	}
}

func TestCopyStringArray(t *testing.T) {
	src := []string{"a", "b", "c"}
	dst := CopyStringArray(src)
	dst[0] = "x"
	assert.Equal(t, "a", src[0], "TestCopyStringArray")
	assert.Equal(t, "x", dst[0], "TestCopyStringArray")
}
