package client

import (
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
)

func Main(args []string) {
	var store string
	var err error

	flags := flag.NewFlagSet("secrt", flag.ContinueOnError)
	flags.StringVar(&store, "c", GetStoreLocation(), "path to configuration")
	if err := flags.Parse(os.Args[1:]); err != nil {
		secrt.Exit(1, err)
	}

	config, err := LoadClientConfig(store)
	if err != nil {
		secrt.Exit(1, err)
	}

	if config.Version != ConfigVersion {
		panic(fmt.Errorf("unexpected config version: %d", config.Version))
	}

	if flags.NArg() == 0 {
		secrt.Usage()
	}

	// sanity check for config file
	if config.Properties.DefaultEndpoint >= len(config.Endpoints) {
		config.Properties.DefaultEndpoint = 0
	}

	var endpoint *Endpoint
	if len(config.Endpoints) > 0 {
		endpoint = config.Endpoints[config.Properties.DefaultEndpoint]
	}

	command := flags.Args()[0]
	args = flags.Args()[1:]

	// Special case when there is no existing config/endpoint
	if endpoint == nil {
		if command != "enrol" {
			fmt.Fprintf(os.Stderr, "please enrol your public key before using `secret`:\n")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "    secret enrol email@example.com\n")
			os.Exit(1)
		} else {
			err = CmdEnrol(config, args)
			if err == nil {
				os.Exit(0)
			}

			secrt.Exit(1, err)
			return
		}
	}

	switch command {
	case "enrol":
		err = CmdEnrol(config, args)

	case "key":
		err = CmdKey(endpoint)

	case "send":
		err = CmdSend(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "ls":
		err = CmdLs(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "get":
		err = CmdGet(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "peer":
		err = CmdPeer(config, endpoint, args)
		if err == nil {
			err = config.Save()
		}

	case "rm":
		err = CmdRm(config, endpoint, args)

	case "set":
		if len(args) != 1 {
			secrt.Usage()
		}

		err = config.Set(args[0])
		if err == nil {
			err = config.Save()
		}

	case "invite":
		err = CmdInvite(config, endpoint, args)

	case "genkey":
		CmdGenKey()

	case "help", "--help", "-h":
		secrt.Usage()

	default:
		secrt.Usage()
	}

	if err == nil {
		os.Exit(0)
	}

	secrt.Exit(1, err)
}
