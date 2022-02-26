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
		_, _ = f.WriteString(`#!/bin/sh
echo "foo"
echo $POSTEE_EVENT
echo $INPUT_ENV`)

		ec := ExecClient{
			ExecCmd:   exec.Command,
			InputFile: f.Name(),
			Env:       []string{"INPUT_ENV=input foo env var"},
		}
		require.NoError(t, ec.Send(map[string]string{
			"description": "foo bar baz env variable",
		}))

		assert.Equal(t, `foo
foo bar baz env variable
input foo env var
`, string(ec.Output))
		assert.Equal(t, ec.Env, []string{"INPUT_ENV=input foo env var"})
	})

	t.Run("sad path - exec fails", func(t *testing.T) {
		ec := ExecClient{
			ExecCmd: fakeExecCmdFailure,
		}
		require.EqualError(t, ec.Send(map[string]string{
			"description": "foo bar baz",
		}), "error while executing script: exit status 1, output: failure")
	})

}
