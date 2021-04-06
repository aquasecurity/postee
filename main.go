package main

import (
	"fmt"
	"github.com/aquasecurity/postee/alertmgr"
	"github.com/aquasecurity/postee/utils"
	"github.com/aquasecurity/postee/webserver"
	"github.com/spf13/cobra"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
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

		if os.Getenv("AQUAALERT_TLS") != "" {
			tls = os.Getenv("AQUAALERT_TLS")
		}

		if os.Getenv("AQUAALERT_CFG") != "" {
			cfgfile = os.Getenv("AQUAALERT_CFG")
		}

		go alertmgr.Instance().Start(cfgfile)
		defer alertmgr.Instance().Terminate()

		go webserver.Instance().Start(url, tls)
		defer webserver.Instance().Terminate()

		Daemonize()
	}
	rootCmd.Execute()
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
