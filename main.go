package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/nats-io/nats-server/v2/server"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/utils"
	"github.com/aquasecurity/postee/v2/webserver"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

const (
	URL       = "0.0.0.0:8082"
	TLS       = "0.0.0.0:8445"
	URL_USAGE = "The socket to bind to, specified using host:port."
	TLS_USAGE = "The TLS socket to bind to, specified using host:port."
	//	CFG_USAGE  = "The folder which contains alert configuration files."
	//	CFG_FOLDER = "/config/"
	CFG_FILE  = "/config/cfg.yaml"
	CFG_USAGE = "The alert configuration file."
)

var (
	url            = ""
	tls            = ""
	cfgfile        = ""
	runnerMode     = false
	controllerMode = false
	runnerName     = ""
	controllerURL  = ""
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

	rootCmd.Flags().BoolVar(&runnerMode, "runner-mode", false, "run postee in runner mode")
	rootCmd.Flags().StringVar(&runnerName, "runner-name", "", "postee runner name")
	rootCmd.Flags().StringVar(&controllerURL, "controller-url", "", "postee controller URL")
	rootCmd.Flags().BoolVar(&controllerMode, "controller-mode", false, "run postee in controller mode")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitDebug()

	rootCmd.Run = func(cmd *cobra.Command, args []string) {

		if runnerMode {
			fmt.Println(">>>>> running in runner mode")
			if runnerName == "" {
				panic("please specify runner name")
			}

			if controllerURL == "" {
				panic("please specify controller url")
			}

			nc, err := nats.Connect(controllerURL, router.SetupConnOptions(nil)...)
			if err != nil {
				panic(err)
			}

			cfgSubj := "config.postee"
			msg, err := nc.Request(cfgSubj, []byte(runnerName), time.Second*5)
			if err != nil {
				panic(err)
			}
			fmt.Println(">>>> config obtained")

			//configData := strings.ReplaceAll(string(msg.Data), "8082", "9082")
			f, err := ioutil.TempFile("", "temp-config-*") // TODO: Find a better way
			if err != nil {
				panic(err)
			}
			f.Write(msg.Data)
			cfgfile = f.Name()

			url = "0.0.0.0:9082" // TODO: Change for runner to prevent conflict, Randomize?
			tls = "0.0.0.0:9445"

			// Subscribe to events
			//eventSubj := "events." + runnerName
			//nc.Subscribe(eventSubj, func(msg *nats.Msg) {
			//
			//})
		}

		var configCh chan *nats.Msg
		var natsServer *server.Server
		if controllerMode {
			fmt.Println(">>>> running in controller mode")
			var err error
			natsServer, err = server.NewServer(&server.Options{})
			if err != nil {
				panic(err)
			}
			go natsServer.Start()
			if !natsServer.ReadyForConnections(time.Second * 10) {
				panic("not ready for connections")
			}

			configCh = make(chan *nats.Msg)
			nc, err := nats.Connect(natsServer.ClientURL(), router.SetupConnOptions(nil)...)
			if err != nil {
				panic(err)
			}
			nc.ChanSubscribe("config.postee", configCh)

			//b, _ := ioutil.ReadFile(cfgfile)

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

		r := router.Instance()
		r.ConfigCh = configCh
		if runnerMode {
			r.ControllerURL = controllerURL
		}
		r.NatsServer = natsServer
		r.RunnerName = runnerName

		if controllerMode {
			r.Mode = "controller"
		} else if runnerMode {
			r.Mode = "runner"
		}

		err := r.Start(cfgfile)
		if err != nil {
			log.Printf("Can't start alert manager %v", err)
			return
		}

		defer r.Terminate()

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
