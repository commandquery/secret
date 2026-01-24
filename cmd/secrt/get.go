package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// CmdGet gets a secret. You can use either the short, 8-character UUID, or the full UUID
// If there's more than one secret with the same short ID, the server will send us an error.
func CmdGet(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("get", flag.ContinueOnError)
	targetFilename := flags.String("o", "", "output to the given filename")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("unable to parse flags: %w", err)
	}

	args = flags.Args()
	if len(args) != 1 {
		return fmt.Errorf("message ID not specified")
	}

	var message secrt.Message
	if err := Call(endpoint, jtp.Nil, &message, "GET", "message", args[0]); err != nil {
		return fmt.Errorf("unable to get message %s: %w", args[0], err)
	}

	cleartext, err := endpoint.Decrypt(config, message.Sender, message.Payload)

	if err != nil {
		return fmt.Errorf("unable to decrypt message: %w", err)
	}

	var target = os.Stdout
	if *targetFilename != "" {
		target, err = os.OpenFile(*targetFilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("unable to open output file %s: %w", *targetFilename, err)
		}
	}

	defer target.Close()

	_, err = target.Write(cleartext)
	if err != nil {
		return err
	}

	return nil
}
