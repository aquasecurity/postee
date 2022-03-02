package outputs

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocketClient_Send(t *testing.T) {
	dc := DocketClient{
		Name:      "my-docker-action",
		ImageName: "docker.io/library/alpine",
		Cmd:       []string{"echo", "hello world"},
	}
	require.NoError(t, dc.Init())
	dc.Send(nil)
}
