package data

import (
	"testing"
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
