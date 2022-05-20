package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/aquasecurity/postee/v2/controller"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/runner"
	"github.com/aquasecurity/postee/v2/utils"
	"github.com/aquasecurity/postee/v2/webserver"
	"github.com/spf13/cobra"
)

const (
	URL       = "0.0.0.0:8082"
	TLS       = "0.0.0.0:8445"
	URL_USAGE = "The socket to bind to, specified using host:port."
	TLS_USAGE = "The TLS socket to bind to, specified using host:port."
	CFG_FILE  = "/config/cfg.yaml"
	CFG_USAGE = "The alert configuration file."
)

var (
	url            = ""
	tls            = ""
	cfgfile        = ""
	controllerMode = false

	controllerURL          = ""
	controllerCARootPath   = ""
	controllerTLSCertPath  = ""
	controllerTLSKeyPath   = ""
	controllerSeedFilePath = ""
	runnerSeedFilePath     = ""

	runnerName        = ""
	runnerCARootPath  = ""
	runnerTLSCertPath = ""
	runnerTLSKeyPath  = ""
)

var rootCmd = &cobra.Command{
	Use:   "webhooksrv",
	Short: fmt.Sprintf("Aqua Container Security Webhook server\n"),
	Long:  fmt.Sprintf("Aqua Container Security Webhook server\n"),
}

func init() {
	rootCmd.Flags().StringVar(&url, "url", URL, URL_USAGE)
	rootCmd.Flags().StringVar(&tls, "tls", TLS, TLS_USAGE)
	rootCmd.Flags().StringVar(&cfgfile, "cfgfile", CFG_FILE, CFG_USAGE)

	rootCmd.Flags().BoolVar(&controllerMode, "controller-mode", false, "run postee in controller mode")
	rootCmd.Flags().StringVar(&controllerURL, "controller-url", "", "postee controller URL")
	rootCmd.Flags().StringVar(&controllerCARootPath, "controller-ca-root", "", "postee controller ca root file")
	rootCmd.Flags().StringVar(&controllerTLSCertPath, "controller-tls-cert", "", "postee controller TLS cert file")
	rootCmd.Flags().StringVar(&controllerTLSKeyPath, "controller-tls-key", "", "postee controller TLS key file")
	rootCmd.Flags().StringVar(&controllerSeedFilePath, "controller-seed-file", "", "postee controller AuthN seed file")

	rootCmd.Flags().StringVar(&runnerName, "runner-name", "", "postee runner name")
	rootCmd.Flags().StringVar(&runnerCARootPath, "runner-ca-root", "", "postee runner ca root file")
	rootCmd.Flags().StringVar(&runnerTLSCertPath, "runner-tls-cert", "", "postee runner tls cert file")
	rootCmd.Flags().StringVar(&runnerTLSKeyPath, "runner-tls-key", "", "postee runner tls key file")
	rootCmd.Flags().StringVar(&runnerSeedFilePath, "runner-seed-file", "", "postee runner AuthN seed file")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitDebug()

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		rtr := router.Instance()

		if runnerName != "" {
			if controllerMode {
				log.Fatal("postee cannot run as a controller when running in runner mode")
			}

			f, err := ioutil.TempFile("", "temp-postee-config-*") // TODO: Find a better way
			if err != nil {
				log.Fatal("Unable to create temp file for runner config on disk: ", err)
			}

			rnr := runner.Runner{
				ControllerURL:      controllerURL,
				RunnerSeedFilePath: runnerSeedFilePath,
				RunnerCARootPath:   runnerCARootPath,
				RunnerTLSKeyPath:   runnerTLSKeyPath,
				RunnerTLSCertPath:  runnerTLSCertPath,
				RunnerName:         runnerName,
			}
			if err := rnr.Setup(rtr, f); err != nil {
				log.Fatal("Failed to launch runner: ", err)
			}
			defer func() { os.Remove(f.Name()) }()

			cfgfile = f.Name()
		}

		if controllerMode {
			if runnerName != "" {
				log.Fatal("postee cannot run as a runner when running in controller mode")
			}

			ctr := controller.Controller{
				ControllerURL:          controllerURL,
				ControllerSeedFilePath: controllerSeedFilePath,
				ControllerCAFile:       controllerCARootPath,
				ControllerTLSKeyPath:   controllerTLSKeyPath,
				ControllerTLSCertPath:  controllerTLSCertPath,
				RunnerName:             runnerName,
			}
			if err := ctr.Setup(rtr); err != nil {
				log.Fatal("Failed to launch controller: ", err)
			}
		}

		if os.Getenv("AQUAALERT_URL") != "" {
			url = os.Getenv("AQUAALERT_URL")
		}

		if os.Getenv("POSTEE_HTTP") != "" {
			url = os.Getenv("POSTEE_HTTP")
		}

		if os.Getenv("AQUAALERT_TLS") != "" {
			tls = os.Getenv("AQUAALERT_TLS")
		}

		if os.Getenv("POSTEE_HTTPS") != "" {
			tls = os.Getenv("POSTEE_HTTPS")
		}

		if os.Getenv("AQUAALERT_CFG") != "" {
			cfgfile = os.Getenv("AQUAALERT_CFG")
		}

		if os.Getenv("POSTEE_CFG") != "" {
			cfgfile = os.Getenv("POSTEE_CFG")
		}

		if os.Getenv("PATH_TO_DB") != "" {
			dbservice.SetNewDbPathFromEnv()
		}

		err := rtr.Start(cfgfile)
		if err != nil {
			log.Printf("Can't start alert manager %v", err)
			return
		}

		defer rtr.Terminate()

		go webserver.Instance().Start(url, tls)
		defer webserver.Instance().Terminate()

		Daemonize()
	}
	err := rootCmd.Execute()
	if err != nil {
		log.Printf("Can't start command %v", err)
		return
	}
}

func Daemonize() {
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		log.Println(sig)
		done <- true
	}()

	<-done
}
