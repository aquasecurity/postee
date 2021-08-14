package router

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/outputs"
	"github.com/stretchr/testify/assert"
)

func TestAquaServerUrl(t *testing.T) {
	AquaServerUrl("http://localhost:8080")
	assert.Equal(t, "http://localhost:8080/#/images/", Instance().aquaServer, "AquaServerUrl")

}

var outputSettings = &data.OutputSettings{
	Type:   "slack",
	Name:   "my-slack",
	Url:    "https://hooks.slack.com/services/TAAAA/BBB/",
	Enable: true,
}

func TestAddOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Contains(t, Instance().outputs, "my-slack")
	assert.Equal(t, "my-slack", Instance().outputs["my-slack"].GetName(), "check name failed")
	assert.Equal(t, "*outputs.SlackOutput", fmt.Sprintf("%T", Instance().outputs["my-slack"]), "check name failed")

}

func TestDeleteOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	DeleteOutput("my-slack")
	assert.Equal(t, 0, len(Instance().outputs), "no outputs expected")

}
func TestEditOutput(t *testing.T) {
	modifiedUrl := "https://hooks.slack.com/services/TAAAA/XXX/"
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	s := Instance().outputs["my-slack"].CloneSettings()

	s.Url = modifiedUrl

	UpdateOutput(s)

	assert.Equal(t, 1, len(Instance().outputs), "one output expected")
	assert.Equal(t, modifiedUrl, Instance().outputs["my-slack"].(*outputs.SlackOutput).Url, "url is updated")

}
func TestListOutput(t *testing.T) {
	AddOutput(outputSettings)
	assert.Equal(t, 1, len(Instance().outputs), "one output expected")

	outputs := ListOutputs()

	assert.Equal(t, 1, len(outputs), "one output expected")

	r := outputs[0]

	assert.Equal(t, "my-slack", r.Name, "check name failed")
	assert.Equal(t, "slack", r.Type, "check type failed")
	assert.True(t, r.Enable, "output must be enabled")

}
