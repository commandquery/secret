package main

import (
	"fmt"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// Activate an enrolment given a token and code.

func CmdActivate(config *Config, endpoint *Endpoint, args []string) error {

	if len(args) != 2 {
		return fmt.Errorf("usage: secrt activate <token> <code>")
	}

	code, err := strconv.Atoi(args[1])
	if err != nil {
		return fmt.Errorf("invalid code: %v", err)
	}

	activationRequest := &secrt.ActivationRequest{
		Token: args[0],
		Code:  code,
	}

	return Call(endpoint, activationRequest, jtp.Nil, "POST", "activate")
}
