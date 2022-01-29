package outputs

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeExecCmdFailure(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestShellProcessFail", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_TEST_PROCESS=1"}
	return cmd
}

func TestShellProcessFail(t *testing.T) {
	if os.Getenv("GO_TEST_PROCESS") != "1" {
		return
	}
	fmt.Fprint(os.Stderr, "failure")
	os.Exit(1)
}

func TestExecClient_Init(t *testing.T) {
	ec := ExecClient{}
	require.NoError(t, ec.Init())
}

func TestExecClient_GetName(t *testing.T) {
	ec := ExecClient{}
	require.NoError(t, ec.Init())
	require.Equal(t, "Exec Output", ec.GetName())
}

func TestExecClient_Send(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		f, err := ioutil.TempFile("", "TestExecClient_Send-*")
		require.NoError(t, err)
		defer func() { os.RemoveAll(f.Name()) }()
		f.WriteString(`#!/bin/sh
echo "foo"`)

		ec := ExecClient{
			ExecCmd:   exec.Command,
			InputFile: f.Name(),
		}
		require.NoError(t, ec.Send(map[string]string{
			"description": "foo bar baz env variable",
		}))

		assert.Equal(t, `foo
`, string(ec.Output))
		assert.Contains(t, ec.Env, "POSTEE_EVENT=foo bar baz env variable")
	})

	t.Run("sad path - exec fails", func(t *testing.T) {
		ec := ExecClient{
			ExecCmd: fakeExecCmdFailure,
		}
		require.EqualError(t, ec.Send(map[string]string{
			"description": "foo bar baz",
		}), "error while executing script: exit status 1")
	})

}
