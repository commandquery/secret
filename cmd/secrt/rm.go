package main

import (
	"fmt"
)

// CmdRm asks the server to delete a message.
func CmdRm(config *Config, endpoint *Endpoint, args []string) error {

	if err := Call(endpoint, EMPTY, EMPTY, "DELETE", "message", args[0]); err != nil {
		return fmt.Errorf("unable to remove message: %w", err)
	}

	return nil
}
