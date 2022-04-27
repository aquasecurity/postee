package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/tidwall/gjson"

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
	Network   string
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
	parsedCmd := d.parseCmd(m)

	r, err := d.client.ImagePull(ctx, d.ImageName, types.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("docker action failed to pull docker image: %w", err)
	}
	defer r.Close()

	var hc container.HostConfig
	if len(d.Volumes) > 0 {
		for src, dst := range d.Volumes {
			hc.Mounts = append(hc.Mounts, mount.Mount{Type: mount.TypeBind, Source: src, Target: dst})
		}
	}
	if len(d.Network) > 0 {
		hc.NetworkMode = container.NetworkMode(d.Network)
	}

	env := append(d.Env, fmt.Sprintf(`POSTEE_EVENT="%s"`, m["description"]))

	ctrName := fmt.Sprintf("postee-%s-%s", d.GetName(), d.uuidNew())
	_, err = d.client.ContainerCreate(ctx, &container.Config{
		Image: d.ImageName,
		Cmd:   parsedCmd,
		Env:   env,
	}, &hc, nil, nil, ctrName)
	if err != nil {
		return fmt.Errorf("docker action failed to create docker container: %w", err)
	}
	defer func() {
		_ = d.client.ContainerRemove(ctx, ctrName, types.ContainerRemoveOptions{Force: true})
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
	_, _ = stdcopy.StdCopy(&buf, &buf, out)
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

func (d DockerClient) parseCmd(input map[string]string) (parsedCmds []string) {
	for _, c := range d.Cmd {
		var calcVal string
		if strings.HasPrefix(c, regoInputPrefix) {
			if ok := json.Valid([]byte(input["description"])); ok { // input is json
				calcVal = gjson.Get(input["description"], strings.TrimPrefix(c, regoInputPrefix+".")).String()
			} else {
				calcVal = input["description"] // input is a string
			}
		} else {
			calcVal = c // no rego to parse
		}
		parsedCmds = append(parsedCmds, calcVal)
	}
	return
}
