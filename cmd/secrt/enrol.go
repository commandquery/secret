package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/commandquery/secrt"
)

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

func EnrolWalkthrough(config *Config) error {
	fmt.Print(`
welcome to secrt.

secrt is a simple tool that lets you easily and securely share confidential information.

secrt uses your email address for identity and sharing, and a server (app.secrt.io) to store
public keys and forward encrypted messages.

secrt creates and stores your private key securely on your device, and no other data
- encrypted or otherwise - is ever shared, other than to provide the service itself.

let's get started with your email address: `)

	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		return fmt.Errorf("unable to read from stdin")
	}
	email := scanner.Text() // already trimmed

	if !peerRegexp.MatchString(email) {
		return fmt.Errorf("invalid email: %s", email)
	}

	// TODO: call enrol API with email address

	fmt.Print(`
please check your inbox for a confirmation email, and open the link provided.

waiting for confirmation...`)

	// TODO: server should default to app.secrt.io

	if err := config.AddEndpoint(email, "http://localhost:8080/", "platform", false); err != nil {
		if errors.Is(err, ErrExistingEnrolment) {
			secrt.Exit(1, fmt.Errorf("unable to enrol user: %w; use --force to override", err))
		} else {
			secrt.Exit(1, fmt.Errorf("unable to enrol user: %w", err))
		}
	}

	// TODO: call wait API

	// Set the default endpoint to the new endpoint. I think this is probably
	// the behaviour you'd expect after enrolling with a new server.
	config.Properties.DefaultEndpoint = len(config.Endpoints) - 1

	return config.Save()
}
