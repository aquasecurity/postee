package outputs

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/aquasecurity/postee/layout"
)

type ExecClient struct {
	Name      string
	InputFile string
}

func (e *ExecClient) GetName() string {
	return e.Name
}

func (e *ExecClient) Init() error {
	e.Name = "Exec Output"
	return nil
}

func (e *ExecClient) Send(m map[string]string) error {
	// Set Postee event to be available inside the execution shell
	cmd := exec.Command("/bin/sh", e.InputFile)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("POSTEE_EVENT=%s", m["description"]))

	var out []byte
	var err error
	if out, err = cmd.CombinedOutput(); err != nil {
		log.Printf("error while executing script: %s", err.Error())
		return err
	}
	log.Println("execution output: ", "len: ", len(out), "out: ", string(out))
	return nil
}

func (e *ExecClient) Terminate() error {
	log.Printf("Exec output terminated\n")
	return nil
}

func (e *ExecClient) GetLayoutProvider() layout.LayoutProvider {
	return nil
}
