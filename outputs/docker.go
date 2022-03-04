package outputs

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/aquasecurity/postee/v2/layout"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/google/uuid"
)

type DockerClient struct {
	client  client.APIClient
	uuidNew func() uuid.UUID

	Name      string
	ImageName string
	Cmd       []string
	Volumes   map[string]string
	Env       []string
}

func (d DockerClient) GetName() string {
	return d.Name
}

func (d *DockerClient) Init() error {
	var err error
	d.client, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to initialize docker action: %w", err)
	}
	d.uuidNew = uuid.New

	log.Println("docker action successfully initialized")
	return nil
}

func (d DockerClient) Send(m map[string]string) error {
	ctx := context.Background()

	_, err := d.client.ImagePull(ctx, d.ImageName, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("docker action failed to pull docker image: %w", err)
	}

	var hc container.HostConfig
	if len(d.Volumes) > 0 {
		for src, dst := range d.Volumes {
			hc.Mounts = append(hc.Mounts, mount.Mount{Type: mount.TypeBind, Source: src, Target: dst})
		}
	}
	d.Env = append(d.Env, fmt.Sprintf("POSTEE_EVENT=%s", m["description"]))

	ctrName := fmt.Sprintf("postee-%s-%s", d.GetName(), d.uuidNew())
	_, err = d.client.ContainerCreate(ctx, &container.Config{
		Image: d.ImageName,
		Cmd:   d.Cmd,
		Env:   d.Env,
	}, &hc, nil, nil, ctrName)
	if err != nil {
		return fmt.Errorf("docker action failed to create docker container: %w", err)
	}
	defer func() {
		d.client.ContainerRemove(ctx, ctrName, types.ContainerRemoveOptions{Force: true})
	}()
	if err := d.client.ContainerStart(ctx, ctrName, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("docker action failed to start container: %w", err)
	}

	statusCh, errCh := d.client.ContainerWait(ctx, ctrName, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("docker action failed running container: %w", err)
		}
	case <-statusCh:
	}

	out, err := d.client.ContainerLogs(ctx, ctrName, types.ContainerLogsOptions{
		ShowStdout: true})
	if err != nil {
		return fmt.Errorf("docker action unable to fetch container logs: %w", err)
	}

	var buf bytes.Buffer
	stdcopy.StdCopy(&buf, &buf, out)
	log.Println("docker action ran successfully, container logs: ", buf.String())
	return nil
}

func (d DockerClient) Terminate() error {
	if err := d.client.Close(); err != nil {
		return fmt.Errorf("docker action unable to terminate: %w", err)
	}
	log.Println("docker action terminated successfully")
	return nil
}

func (d DockerClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
