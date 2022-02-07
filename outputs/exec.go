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
	e.Env = os.Environ()
	e.Env = append(e.Env, fmt.Sprintf("POSTEE_EVENT=%s", m["description"]))

	// Set Postee event to be available inside the execution shell
	cmd := e.ExecCmd("/bin/sh", e.InputFile)
	cmd.Env = append(cmd.Env, e.Env...)

	var err error
	if e.Output, err = cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error while executing script: %s", err.Error())
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
