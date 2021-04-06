package data

import "testing"

const (
	dist     = "dist"
	image    = "image"
	register = "reg"
	want     = "dist-image-reg"
)

func TestBuildUniqueId(t *testing.T) {
	if got := BuildUniqueId(dist, image, register); got != want {
		t.Errorf("BuildUniqueId(%q, %q, %q) == %q, want %q", dist, image, register, got, want)
	}
}

func TestGetUniqueId(t *testing.T) {
	si := &ScanImageInfo{
		Image:    image,
		Registry: register,
		Digest:   dist,
	}
	if got := si.GetUniqueId(); got != want {
		t.Errorf(".GetUniqueId() == %q, want %q", got, want)
	}
}
