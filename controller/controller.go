package controller

import (
	gotls "crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/aquasecurity/postee/v2/router"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

const (
	NATSEventSubject  = "postee.events"
	NATSConfigSubject = "postee.config"
)

type Controller struct {
	ControllerURL          string
	ControllerSeedFilePath string
	ControllerCAFile       string
	ControllerTLSKeyPath   string
	ControllerTLSCertPath  string
	RunnerName             string
}

func (c Controller) Setup(r *router.Router) error {
	log.Println("Running in controller mode")

	var configCh chan *nats.Msg
	var natsServer *server.Server

	var host string
	var port int
	if c.ControllerURL != "" {
		var portString string
		u, err := url.Parse(c.ControllerURL)
		if err != nil {
			return fmt.Errorf("invalid controller url specified: %s", c.ControllerURL)
		}
		host, portString, _ = net.SplitHostPort(u.Host)
		port, _ = strconv.Atoi(portString)
	}

	var err error
	if c.ControllerTLSKeyPath != "" && c.ControllerTLSCertPath != "" {
		var tlsConfig *gotls.Config
		tlsConfig, err = server.GenTLSConfig(&server.TLSConfigOpts{
			CertFile: c.ControllerTLSCertPath,
			KeyFile:  c.ControllerTLSKeyPath,
			CaFile:   c.ControllerCAFile,
		})
		if err != nil {
			return fmt.Errorf("invalid TLS config: %s", err)
		}

		var pubKey string
		var nKeys []*server.NkeyUser
		if c.ControllerSeedFilePath != "" {
			log.Println("Seedfile specified for Controller, enabling AuthN")
			sf, err := ioutil.ReadFile(c.ControllerSeedFilePath)
			if err != nil {
				return fmt.Errorf("unable to read seed file: %s", err)
			}

			nKey, err := nkeys.ParseDecoratedNKey(sf)
			if err != nil {
				return fmt.Errorf("unable to parse seed file: %s", err)
			}

			pubKey, err = nKey.PublicKey()
			if err != nil {
				return fmt.Errorf("unable to get public key: %s", err)
			}

			nKeys = append(nKeys, &server.NkeyUser{Nkey: pubKey})
		}

		natsServer, err = server.NewServer(&server.Options{
			TLSConfig: tlsConfig,
			Nkeys:     nKeys,
			Host:      host,
			Port:      port,
		})
	} else {
		natsServer, err = server.NewServer(&server.Options{Host: host, Port: port})
	}
	if err != nil {
		return fmt.Errorf("unable to start controller backplane: %s", err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(time.Second * 10) {
		return fmt.Errorf("controller backplane is not ready to receive connections, try restarting controller")
	}

	log.Println("Controller listening for requests on: ", natsServer.ClientURL())
	configCh = make(chan *nats.Msg)

	var opts []nats.Option
	var nKeyOpt nats.Option
	if c.ControllerSeedFilePath != "" {
		nKeyOpt, err = nats.NkeyOptionFromSeed(c.ControllerSeedFilePath)
		if err != nil {
			return fmt.Errorf("unable to load seed file: %s", err)
		}
	}
	opts = append(opts, nKeyOpt)

	var nc *nats.Conn
	if c.ControllerCAFile != "" {
		opts = append(opts, nats.RootCAs(c.ControllerCAFile))
	}
	nc, err = nats.Connect(natsServer.ClientURL(), router.SetupConnOptions(opts)...)
	if err != nil {
		return fmt.Errorf("unable to setup controller: %s", err)
	}

	log.Println("Listening to config requests on: ", NATSConfigSubject)
	if _, err := nc.ChanSubscribe(NATSConfigSubject, configCh); err != nil {
		return fmt.Errorf("unable to subscribe for config requests from runners on: %s, err: %s", NATSConfigSubject, err)
	}

	r.ConfigCh = configCh
	r.NatsServer = natsServer
	r.Mode = "controller"

	r.NatsMsgCh = make(chan *nats.Msg)
	eventSubj := NATSEventSubject
	log.Println("Subscribing to events from runners on: ", eventSubj)
	if _, err := nc.ChanSubscribe(eventSubj, r.NatsMsgCh); err != nil {
		return fmt.Errorf("unable to subscribe for events from runners on: %s, err: %s", eventSubj, err)
	}

	return nil
}
