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
  issuetype: ""
  name: my-exec-from-runner
  runs-on: postee-runner-1
  type: exec
  unknowns: null
- body-content: |
    This is an another example of a inline body
    Event ID: event.input.SigMetadata.ID
  enable: true
  issuetype: ""
  method: POST
  name: my-http-post-from-runner
  runs-on: postee-runner-1
  type: http
  unknowns: null
  url: https://webhook.site/<uuid>
db-verify-interval: 1
max-db-size: 1000MB
routes:
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-1")
  input-files: null
  name: runner-only-route
  plugins:
    AggregateTimeoutSeconds: 0
    UniqueMessageTimeoutSeconds: 0
    aggregate-message-number: 0
    aggregate-message-timeout: ""
    unique-message-props: null
    unique-message-timeout: ""
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-2")
  input-files: null
  name: controller-runner-route
  plugins:
    AggregateTimeoutSeconds: 0
    UniqueMessageTimeoutSeconds: 0
    aggregate-message-number: 0
    aggregate-message-timeout: ""
    unique-message-props: null
    unique-message-timeout: ""
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-1")
  input-files: null
  name: runner-only-route
  plugins:
    AggregateTimeoutSeconds: 0
    UniqueMessageTimeoutSeconds: 0
    aggregate-message-number: 0
    aggregate-message-timeout: ""
    unique-message-props: null
    unique-message-timeout: ""
  serialize-actions: true
  template: raw-json
- actions:
  - my-exec-from-runner
  - my-http-post-from-runner
  input: contains(input.SigMetadata.ID, "TRC-2")
  input-files: null
  name: controller-runner-route
  plugins:
    AggregateTimeoutSeconds: 0
    UniqueMessageTimeoutSeconds: 0
    aggregate-message-number: 0
    aggregate-message-timeout: ""
    unique-message-props: null
    unique-message-timeout: ""
  serialize-actions: true
  template: raw-json
templates:
- body: ""
  legacy-scan-renderer: ""
  name: raw-json
  rego-package: postee.rawmessage.json
  url: ""
- body: ""
  legacy-scan-renderer: ""
  name: raw-json
  rego-package: postee.rawmessage.json
  url: ""
- body: ""
  legacy-scan-renderer: ""
  name: raw-json
  rego-package: postee.rawmessage.json
  url: ""
- body: ""
  legacy-scan-renderer: ""
  name: raw-json
  rego-package: postee.rawmessage.json
  url: ""`,
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
