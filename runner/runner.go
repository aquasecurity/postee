package runner

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/postee/v2/router"
	"github.com/nats-io/nats.go"
)

const (
	NATSConfigSubject = "postee.config"
)

type Runner struct {
	ControllerURL      string
	RunnerSeedFilePath string
	RunnerCARootPath   string
	RunnerTLSKeyPath   string
	RunnerTLSCertPath  string
	RunnerName         string
}

func (r Runner) Setup(rtr *router.Router, cfg *os.File) error {
	log.Println("Running in runner mode")

	if r.ControllerURL == "" {
		return fmt.Errorf("runner mode requires a valid controller url")
	}

	var opts []nats.Option
	var nKeyOpt nats.Option
	if r.RunnerSeedFilePath != "" {
		log.Println("Seedfile specified for Runner, enabling AuthN")
		var err error
		nKeyOpt, err = nats.NkeyOptionFromSeed(r.RunnerSeedFilePath)
		if err != nil {
			return fmt.Errorf("unable to parse seed file: %w", err)
		}
		opts = append(opts, nKeyOpt)
	}

	if r.RunnerTLSKeyPath != "" && r.RunnerTLSCertPath != "" {
		opts = append(opts, nats.ClientCert(r.RunnerTLSCertPath, r.RunnerTLSKeyPath))
		if r.RunnerCARootPath != "" {
			opts = append(opts, nats.RootCAs(r.RunnerCARootPath))
		}
	}

	var err error
	rtr.NatsConn, err = nats.Connect(r.ControllerURL, router.SetupConnOptions(opts)...)
	if err != nil {
		return fmt.Errorf("unable to connect to controller at url: %s, err: %w", r.ControllerURL, err)
	}

	msg, err := rtr.NatsConn.Request(NATSConfigSubject, []byte(r.RunnerName), time.Second*5)
	if err != nil {
		return fmt.Errorf("unable to obtain runner config from url: %s, err: %w", r.ControllerURL, err)
	}

	if _, err = cfg.Write(msg.Data); err != nil {
		return fmt.Errorf("unable to write runner config to disk: %w", err)
	}
	log.Println("Runner configuration obtained from: ", r.ControllerURL)

	rtr.ControllerURL = r.ControllerURL
	rtr.RunnerName = r.RunnerName
	rtr.Mode = "runner"

	return nil
}
