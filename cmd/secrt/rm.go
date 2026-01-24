package main

import (
	"fmt"

	"github.com/commandquery/secrt/jtp"
)

// CmdRm asks the server to delete a message.
func CmdRm(config *Config, endpoint *Endpoint, args []string) error {

	if err := Call(endpoint, jtp.Nil, jtp.Nil, "DELETE", "message", args[0]); err != nil {
		return fmt.Errorf("unable to remove message: %w", err)
	}

	return nil
}
