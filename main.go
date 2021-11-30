package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/aquasecurity/postee/v2/router"
	"github.com/aquasecurity/postee/v2/utils"
	"github.com/aquasecurity/postee/v2/webserver"
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
	url     = ""
	tls     = ""
	cfgfile = ""
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
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	utils.InitDebug()

	rootCmd.Run = func(cmd *cobra.Command, args []string) {

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

		err := router.Instance().ApplyFileCfg(cfgfile, false)
		if err != nil {
			log.Printf("Can't start alert manager %v", err)
			return
		}

		defer router.Instance().Terminate()

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
