package outputs

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/aquasecurity/postee/v2/layout"
)

type execCmd = func(string, ...string) *exec.Cmd

type ExecClient struct {
	ExecCmd   execCmd
	Name      string
	Env       []string
	InputFile string
	Output    []byte
}

func (e *ExecClient) GetName() string {
	return e.Name
}

func (e *ExecClient) Init() error {
	e.ExecCmd = exec.Command
	e.Name = "Exec Output"
	return nil
}

func (e *ExecClient) Send(m map[string]string) error {
	envVars := os.Environ()
	envVars = append(envVars, e.Env...)
	envVars = append(envVars, fmt.Sprintf("POSTEE_EVENT=%s", m["description"]))

	// Set Postee event to be available inside the execution shell
	cmd := e.ExecCmd("/bin/sh", e.InputFile)
	cmd.Env = append(cmd.Env, envVars...)

	var err error
	if e.Output, err = cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error while executing script: %w", err)
	}
	log.Println("execution output: ", "len: ", len(e.Output), "out: ", string(e.Output))
	return nil
}

func (e *ExecClient) Terminate() error {
	log.Printf("Exec output terminated\n")
	return nil
}

func (e *ExecClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
