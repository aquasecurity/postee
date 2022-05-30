package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_buildRunnerConfig(t *testing.T) {
	testCases := []struct {
		name          string
		cfgFile       string
		want          string
		expectedError string
	}{
		{
			name:    "happy path",
			cfgFile: "goldens/sample.cfg",
			want: `actions:
- enable: true
  env:
  - MY_ENV_VAR=foo_bar_baz
  - MY_KEY=secret
  exec-script: |
    #!/bin/sh
    echo $POSTEE_EVENT
    echo "this is hello from postee"
  name: my-exec-from-runner
  runs-on: postee-runner-1
  type: exec
- body-content: |
    This is an another example of a inline body
    Event ID: event.input.SigMetadata.ID
  enable: true
  method: POST
  name: my-http-post-from-runner
  runs-on: postee-runner-1
  type: http
  url: https://webhook.site/<uuid>
db-verify-interval: 1
max-db-size: 1000MB
routes:
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-1")
  name: runner-only-route
  plugins: {}
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-2")
  name: controller-runner-route
  plugins: {}
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-1")
  name: runner-only-route
  plugins: {}
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-2")
  name: controller-runner-route
  plugins: {}
  serialize-actions: true
  template: raw-json
templates:
- name: raw-json
  rego-package: postee.rawmessage.json`,
		},
		{
			name:          "sad path, config not found",
			cfgFile:       "invalid path",
			expectedError: "open invalid path: no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildRunnerConfig("postee-runner-1", tc.cfgFile)
			switch {
			case tc.expectedError != "":
				assert.Equal(t, tc.expectedError, err.Error(), tc.name)
				assert.Empty(t, got, tc.name)
			default:
				assert.NoError(t, err, tc.name)
				assert.YAMLEq(t, tc.want, got, tc.name)
			}
		})
	}
}
