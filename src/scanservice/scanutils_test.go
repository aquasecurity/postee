package scanservice

import "testing"

func TestCompliesPolicies(t *testing.T) {
	tests := []struct{
		policies []string
		image string
		want bool
	} {
		{[]string{}, "image", false},
		{[]string{":latest", "mongo:1", "mon*:*"}, "all-in-one:3.5.19223", false},
		{[]string{":latest", "mongo:1", "mon*:*"}, "mongo:2.2", true},
		{[]string{":latest", "mongo:1", "mon*:"}, "mongo:2.2", true},
		{[]string{":latest", "mongo:1", }, "mongo:2.2", false},
		{[]string{":latest", "mongo:1", }, "mongo:latest", true},
	}

	for _, test := range tests {
		if got := compliesPolicies(test.policies, test.image); got != test.want {
			t.Errorf("compliesPolicies(%v, %q) == %t, want %t", test.policies, test.image, got, test.want)
		}
	}
}