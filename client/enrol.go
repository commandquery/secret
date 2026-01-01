package client

import (
	"bytes"
	"errors"
	"flag"
	"fmt"

	"github.com/commandquery/secrt"
)

func ReadKeyPhrase() []byte {
	p1 := ReadPassword("Enter passphrase:  ")
	if p1 == nil {
		return nil
	}

	p2 := ReadPassword("Verify passphrase: ")
	if p2 == nil {
		return nil
	}

	if !bytes.Equal(p1, p2) {
		fmt.Println("passphrase mismatch")
		return nil
	}

	return p1
}

func CmdEnrol(config *Config, args []string) error {

	flags := flag.NewFlagSet("enrol", flag.ContinueOnError)
	force := flags.Bool("force", false, "force overwrite")
	storeType := flags.String("store", "platform", "Storage type for private key")
	if err := flags.Parse(args); err != nil {
		secrt.Usage("secret enrol [--force] user@domain https://server/")
	}

	args = flags.Args()
	if len(args) != 2 {
		secrt.Usage("secret enrol [--force] user@domain https://server/")
	}

	if err := config.AddEndpoint(args[0], args[1], KeyStoreType(*storeType), *force); err != nil {
		if errors.Is(err, ErrExistingEnrolment) {
			secrt.Exit(1, fmt.Errorf("unable to enrol user: %w; use --force to override", err))
		} else {
			secrt.Exit(1, fmt.Errorf("unable to enrol user: %w", err))
		}
	}

	// Set the default endpoint to the new endpoint. I think this is probably
	// the behaviour you'd expect after enrolling with a new server.
	config.Properties.DefaultEndpoint = len(config.Endpoints) - 1

	return config.Save()
}
