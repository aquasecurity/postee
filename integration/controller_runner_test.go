//go:build integration

package integration

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/aquasecurity/postee/v2/controller"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	RunnerConfig = `
routes:
- name: terminate-and-notify
  input: contains(input.SigMetadata.ID, "TRC-2")
  actions: [terminate-pod]
  plugins: {}

actions:
- name: terminate-pod
  runs-on: "test-runner-1"
  type: exec
  enable: true
  exec-script: |
    #!/bin/sh
    PID=$(echo $POSTEE_EVENT | jq -r .Context.hostName)
    kubectl delete pod $PID     # If terminating a K8s pod
    # pkill -SIGTERM $PID       # If terminating a UNIX process
`
)

func TestControllerRunner_Happy(t *testing.T) {
	testCases := []struct {
		name           string
		cCfg           controller.Controller
		rCfg           runner.Runner
		expectedConfig string
	}{
		{
			name: "no tls, no auth",
			cCfg: controller.Controller{
				ControllerURL: "nats://0.0.0.0:17777",
				RunnerName:    "test-runner-1",
			},
			rCfg: runner.Runner{
				ControllerURL: "nats://0.0.0.0:17777",
				RunnerName:    "test-runner-1",
			},
			expectedConfig: RunnerConfig,
		},
		{
			name: "with tls, no auth",
			cCfg: controller.Controller{
				ControllerURL:         "tls://0.0.0.0:18888",
				RunnerName:            "test-runner-1",
				ControllerTLSKeyPath:  "goldens/server-key.pem",
				ControllerTLSCertPath: "goldens/server-cert.pem",
				ControllerCAFile:      "goldens/rootCA.pem",
			},
			rCfg: runner.Runner{
				ControllerURL:     "tls://0.0.0.0:18888",
				RunnerName:        "test-runner-1",
				RunnerCARootPath:  "goldens/rootCA.pem",
				RunnerTLSCertPath: "goldens/client-cert.pem",
				RunnerTLSKeyPath:  "goldens/client-key.pem",
			},
			expectedConfig: RunnerConfig,
		},
		{
			name: "with tls, with auth",
			cCfg: controller.Controller{
				ControllerURL:          "tls://0.0.0.0:19999",
				RunnerName:             "test-runner-1",
				ControllerTLSKeyPath:   "goldens/server-key.pem",
				ControllerTLSCertPath:  "goldens/server-cert.pem",
				ControllerCAFile:       "goldens/rootCA.pem",
				ControllerSeedFilePath: "goldens/test-seed.txt",
			},
			rCfg: runner.Runner{
				ControllerURL:      "tls://0.0.0.0:19999",
				RunnerName:         "test-runner-1",
				RunnerCARootPath:   "goldens/rootCA.pem",
				RunnerTLSCertPath:  "goldens/client-cert.pem",
				RunnerTLSKeyPath:   "goldens/client-key.pem",
				RunnerSeedFilePath: "goldens/test-seed.txt",
			},
			expectedConfig: RunnerConfig,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rtr := router.Instance()

			require.NoError(t, tc.cCfg.Setup(rtr))
			require.NoError(t, rtr.Start("goldens/simple.yaml"))

			f, err := ioutil.TempFile("", "TestRunner_Setup-*")
			defer func() { os.Remove(f.Name()) }()
			require.NoError(t, err)
			require.NoError(t, tc.rCfg.Setup(rtr, f))

			got, err := ioutil.ReadFile(f.Name())
			require.NoError(t, err)
			assert.YAMLEq(t, tc.expectedConfig, string(got))

			rtr.Terminate()
		})
	}
}
