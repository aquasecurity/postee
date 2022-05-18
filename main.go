package main

import (
	gotls "crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/utils"
	"github.com/aquasecurity/postee/v2/webserver"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/spf13/cobra"
)

const (
	URL       = "0.0.0.0:8082"
	TLS       = "0.0.0.0:8445"
	URL_USAGE = "The socket to bind to, specified using host:port."
	TLS_USAGE = "The TLS socket to bind to, specified using host:port."
	CFG_FILE  = "/config/cfg.yaml"
	CFG_USAGE = "The alert configuration file."

	NATSConfigSubject = "postee.config"
	NATSEventSubject  = "postee.events"
)

var (
	url            = ""
	tls            = ""
	cfgfile        = ""
	controllerMode = false

	controllerURL          = ""
	controllerTLSCertPath  = ""
	controllerTLSKeyPath   = ""
	controllerSeedFilePath = ""
	runnerSeedFilePath     = ""

	runnerName        = ""
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
	rootCmd.Flags().StringVar(&controllerTLSCertPath, "controller-tls-cert", "", "postee controller TLS cert file")
	rootCmd.Flags().StringVar(&controllerTLSKeyPath, "controller-tls-key", "", "postee controller TLS key file")
	rootCmd.Flags().StringVar(&controllerSeedFilePath, "controller-seed-file", "", "postee controller AuthN seed file")

	rootCmd.Flags().StringVar(&runnerName, "runner-name", "", "postee runner name")
	rootCmd.Flags().StringVar(&runnerTLSCertPath, "runner-tls-cert", "", "postee runner tls cert file")
	rootCmd.Flags().StringVar(&runnerTLSKeyPath, "runner-tls-key", "", "postee runner tls key file")
	rootCmd.Flags().StringVar(&runnerSeedFilePath, "runner-seed-file", "", "postee runner AuthN seed file")
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitDebug()

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		r := router.Instance()

		if runnerName != "" {
			log.Println("Running in runner mode")
			if controllerMode {
				log.Fatal("Postee cannot run as a controller when running in runner mode")
			}

			if controllerURL == "" {
				log.Fatal("Runner mode requires a valid controller url")
			}

			var nKeyOpt nats.Option
			if runnerSeedFilePath != "" {
				log.Println("Seedfile specified for Runner, enabling AuthN")
				var err error
				nKeyOpt, err = nats.NkeyOptionFromSeed(runnerSeedFilePath)
				if err != nil {
					log.Fatal("Unable to parse seed file: ", err)
				}
			}

			var err error
			if runnerTLSKeyPath != "" && runnerTLSCertPath != "" {
				r.NatsConn, err = nats.Connect(controllerURL, nats.ClientCert(runnerTLSCertPath, runnerTLSKeyPath), nKeyOpt)
			} else {
				r.NatsConn, err = nats.Connect(controllerURL, router.SetupConnOptions(nil)...)
			}
			if err != nil {
				log.Fatal("Unable to connect to controller at url: ", controllerURL, " err: ", err)
			}

			msg, err := r.NatsConn.Request(NATSConfigSubject, []byte(runnerName), time.Second*5)
			if err != nil {
				log.Fatal("Unable to obtain runner config from url: ", controllerURL, "err: ", err)
			}

			log.Println("Runner configuration obtained from: ", controllerURL)
			f, err := ioutil.TempFile("", "temp-postee-config-*") // TODO: Find a better way
			if err != nil {
				log.Fatal("Unable to create temp file for runner config on disk: ", err)
			}
			defer func() {
				os.Remove(f.Name())
			}()

			if _, err := f.Write(msg.Data); err != nil {
				log.Fatal("Unable to write runner config to disk: ", err)
			}
			cfgfile = f.Name()

			r.ControllerURL = controllerURL
			r.RunnerName = runnerName
			r.Mode = "runner"
		}

		if controllerMode {
			log.Println("Running in controller mode")
			if runnerName != "" {
				log.Fatal("Postee cannot run as a runner when running in controller mode")
			}

			var configCh chan *nats.Msg
			var natsServer *server.Server

			var err error
			if controllerTLSKeyPath != "" && controllerTLSCertPath != "" {
				var tlsConfig *gotls.Config
				tlsConfig, err = server.GenTLSConfig(&server.TLSConfigOpts{
					CertFile: controllerTLSCertPath,
					KeyFile:  controllerTLSKeyPath,
				})
				if err != nil {
					log.Fatal("Invalid TLS config: ", err)
				}

				var pubKey string
				var nKeys []*server.NkeyUser
				if controllerSeedFilePath != "" {
					log.Println("Seedfile specified for Controller, enabling AuthN")
					sf, err := ioutil.ReadFile(controllerSeedFilePath)
					if err != nil {
						log.Fatal("Unable to read seed file: ", err)
					}

					nKey, err := nkeys.ParseDecoratedNKey(sf)
					if err != nil {
						log.Fatal("Unable to parse seed file: ", err)
					}

					pubKey, err = nKey.PublicKey()
					if err != nil {
						log.Fatal("Unable to get public key: ", err)
					}

					nKeys = append(nKeys, &server.NkeyUser{Nkey: pubKey})
				}

				natsServer, err = server.NewServer(&server.Options{
					TLSConfig: tlsConfig,
					Nkeys:     nKeys,
				})
			} else {
				natsServer, err = server.NewServer(&server.Options{})
			}
			if err != nil {
				log.Fatal("Unable to start controller backplane: ", err)
			}
			go natsServer.Start()
			if !natsServer.ReadyForConnections(time.Second * 10) {
				log.Fatal("Controller backplane is not ready to receive connections, try restarting controller")
			}

			log.Println("Controller listening for requests on: ", natsServer.ClientURL())
			configCh = make(chan *nats.Msg)

			var nKeyOpt nats.Option
			if controllerSeedFilePath != "" {
				nKeyOpt, err = nats.NkeyOptionFromSeed(controllerSeedFilePath)
				if err != nil {
					log.Fatal("Unable to load seed file: ", err)
				}
			}

			var nc *nats.Conn
			nc, err = nats.Connect(natsServer.ClientURL(), router.SetupConnOptions([]nats.Option{nKeyOpt})...)
			if err != nil {
				log.Fatal("Unable to setup controller: ", err)
			}

			log.Println("Listening to config requests on: ", NATSConfigSubject)
			if _, err := nc.ChanSubscribe(NATSConfigSubject, configCh); err != nil {
				log.Fatal("Unable to subscribe for config requests from runners on: ", NATSConfigSubject, "err: ", err)
			}

			r.ConfigCh = configCh
			r.NatsServer = natsServer
			r.Mode = "controller"

			r.NatsMsgCh = make(chan *nats.Msg)
			eventSubj := NATSEventSubject
			log.Println("Subscribing to events from runners on: ", eventSubj)
			if _, err := nc.ChanSubscribe(eventSubj, r.NatsMsgCh); err != nil {
				log.Fatal("Unable to subscribe for events from runners on: ", eventSubj, "err: ", err)
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
