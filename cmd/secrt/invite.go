package main

import (
	"flag"

	"github.com/commandquery/secrt"
)

func CmdInvite(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	if err := flags.Parse(args); err != nil {
		secrt.Usage("secret invite user@domain")
	}

	args = flags.Args()
	if len(args) != 1 {
		secrt.Usage("secret invite user@domain")
	}

	return Call(endpoint, EMPTY, EMPTY, "POST", "invite", args[0])
}
