package main

import (
	"flag"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
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

	return Call(endpoint, jtp.Nil, jtp.Nil, "POST", "invite", args[0])
}
