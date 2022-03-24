package outputs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
)

type mockDockerClient struct {
	client.APIClient

	imagePull       func(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error)
	containerCreate func(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error)
	containerStart  func(ctx context.Context, container string, options types.ContainerStartOptions) error
	containerWait   func(ctx context.Context, container string, condition containertypes.WaitCondition) (<-chan containertypes.ContainerWaitOKBody, <-chan error)
	containerLogs   func(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error)
	containerRemove func(ctx context.Context, container string, options types.ContainerRemoveOptions) error
}

func (m mockDockerClient) ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error) {
	if m.imagePull != nil {
		return m.imagePull(ctx, ref, options)
	}

	return io.NopCloser(strings.NewReader(`pulling image foo bar`)), nil
}

func (m mockDockerClient) ContainerCreate(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error) {
	if m.containerCreate != nil {
		return m.containerCreate(ctx, config, hostConfig, networkingConfig, platform, containerName)
	}

	return containertypes.ContainerCreateCreatedBody{
		ID: "foo-bar-123",
	}, nil
}

func (m mockDockerClient) ContainerStart(ctx context.Context, container string, options types.ContainerStartOptions) error {
	if m.containerStart != nil {
		return m.containerStart(ctx, container, options)
	}

	return nil
}

func (m mockDockerClient) ContainerWait(ctx context.Context, container string, condition containertypes.WaitCondition) (<-chan containertypes.ContainerWaitOKBody, <-chan error) {
	if m.containerWait != nil {
		return m.containerWait(ctx, container, condition)
	}

	resultC := make(chan containertypes.ContainerWaitOKBody)
	errC := make(chan error)

	go func() {
		resultC <- containertypes.ContainerWaitOKBody{
			Error:      nil,
			StatusCode: http.StatusOK,
		}
		errC <- nil
	}()

	return resultC, errC
}

func (m mockDockerClient) ContainerLogs(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error) {
	if m.containerLogs != nil {
		return m.containerLogs(ctx, container, options)
	}

	return io.NopCloser(strings.NewReader("the logs of joy")), nil
}

func (m mockDockerClient) ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error {
	if m.containerRemove != nil {
		return m.containerRemove(ctx, container, options)
	}

	return nil
}

type mockUUID struct {
}

func (mockUUID) New() uuid.UUID {
	return uuid.MustParse("1471d64a-6c64-4527-bbd8-7bc772678db8")
}

func TestDocketClient_Send(t *testing.T) {
	testCases := []struct {
		name           string
		inputEvent     string
		inputDockerCmd []string

		imagePullFunc       func(context.Context, string, types.ImagePullOptions) (io.ReadCloser, error)
		containerCreateFunc func(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error)
		containerRemoveFunc func(ctx context.Context, container string, options types.ContainerRemoveOptions) error
		containerWaitFunc   func(ctx context.Context, container string, condition containertypes.WaitCondition) (<-chan containertypes.ContainerWaitOKBody, <-chan error)
		containerStartFunc  func(ctx context.Context, container string, options types.ContainerStartOptions) error
		containerLogsFunc   func(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error)

		expectedError string
		expectedLogs  string
	}{
		{
			name:         "happy path, string input event",
			inputEvent:   `foo bar baz`,
			expectedLogs: "the logs of joy",
			containerCreateFunc: func(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error) {

				assert.Equal(t, containertypes.Config{
					Image: "docker.io/library/alpine",
					Cmd:   []string{"echo", "hello world"},
					Env:   []string{"FOO=bar", `POSTEE_EVENT="foo bar baz"`},
				}, *config)

				assert.Equal(t, containertypes.HostConfig{
					Mounts: []mount.Mount{{Type: mount.TypeBind, Source: "foo-src", Target: "bar-dst"}}, NetworkMode: "host",
				}, *hostConfig)

				assert.Contains(t, containerName, "postee-my-docker-action")

				return containertypes.ContainerCreateCreatedBody{
					ID: "foo-bar-123",
				}, nil
			},
			containerRemoveFunc: func(ctx context.Context, container string, options types.ContainerRemoveOptions) error {

				assert.Equal(t, "postee-my-docker-action-1471d64a-6c64-4527-bbd8-7bc772678db8", container)
				return nil
			},
		},
		{
			name:           "happy path, relative json input event",
			inputEvent:     `{"hostname":"foo.host"}`,
			inputDockerCmd: []string{"kubectl", "delete", "pod", "event.input.hostname"},
			expectedLogs:   "the logs of joy",
			containerCreateFunc: func(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error) {

				assert.Equal(t, containertypes.Config{
					Image: "docker.io/library/alpine",
					Cmd:   []string{"kubectl", "delete", "pod", "foo.host"},
					Env:   []string{"FOO=bar", `POSTEE_EVENT="{"hostname":"foo.host"}"`},
				}, *config)

				assert.Equal(t, containertypes.HostConfig{
					Mounts: []mount.Mount{{Type: mount.TypeBind, Source: "foo-src", Target: "bar-dst"}}, NetworkMode: "host",
				}, *hostConfig)

				assert.Contains(t, containerName, "postee-my-docker-action")

				return containertypes.ContainerCreateCreatedBody{
					ID: "foo-bar-123",
				}, nil
			},
			containerRemoveFunc: func(ctx context.Context, container string, options types.ContainerRemoveOptions) error {

				assert.Equal(t, "postee-my-docker-action-1471d64a-6c64-4527-bbd8-7bc772678db8", container)
				return nil
			},
		},
		{
			name: "sad path, ImagePull returns an error",
			imagePullFunc: func(ctx context.Context, s string, options types.ImagePullOptions) (io.ReadCloser, error) {
				return nil, fmt.Errorf("failed to pull image")
			},
			expectedError: "docker action failed to pull docker image: failed to pull image",
		},
		{
			name: "sad path, ContainerCreate returns an error",
			containerCreateFunc: func(ctx context.Context, config *containertypes.Config, hostConfig *containertypes.HostConfig, networkingConfig *networktypes.NetworkingConfig, platform *specs.Platform, containerName string) (containertypes.ContainerCreateCreatedBody, error) {
				return containertypes.ContainerCreateCreatedBody{}, fmt.Errorf("container creation failed")
			},
			expectedError: "docker action failed to create docker container: container creation failed",
		},
		{
			name: "sad path, ContainerStart returns an error",
			containerStartFunc: func(ctx context.Context, container string, options types.ContainerStartOptions) error {
				return fmt.Errorf("failed to start")
			},
			expectedError: "docker action failed to start container: failed to start",
		},
		{
			name: "sad path, ContainerWait returns an error",
			containerWaitFunc: func(ctx context.Context, container string, condition containertypes.WaitCondition) (<-chan containertypes.ContainerWaitOKBody, <-chan error) {

				errC := make(chan error)
				go func() {
					errC <- fmt.Errorf("failed to wait")
				}()
				return nil, errC

			},
			expectedError: "docker action failed running container: failed to wait",
		},
		{
			name: "sad path, ContainerLogs returns an error",
			containerLogsFunc: func(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error) {
				return nil, fmt.Errorf("failed to get logs")
			},
			expectedError: "docker action unable to fetch container logs: failed to get logs",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dc := DockerClient{
				Name:      "my-docker-action",
				ImageName: "docker.io/library/alpine",
				Env:       []string{"FOO=bar"},
				Network:   "host",
				Volumes: map[string]string{
					"foo-src": "bar-dst",
				},
				client: &mockDockerClient{
					imagePull:       tc.imagePullFunc,
					containerCreate: tc.containerCreateFunc,
					containerRemove: tc.containerRemoveFunc,
					containerWait:   tc.containerWaitFunc,
					containerStart:  tc.containerStartFunc,
					containerLogs:   tc.containerLogsFunc,
				},
				uuidNew: mockUUID{}.New,
			}

			switch {
			case tc.inputDockerCmd != nil:
				dc.Cmd = tc.inputDockerCmd
			default:
				dc.Cmd = []string{"echo", "hello world"}
			}

			err := dc.Send(map[string]string{"description": tc.inputEvent})
			if tc.expectedError != "" {
				assert.Equal(t, tc.expectedError, err.Error(), tc.name)
			} else {
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
