package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

// Enrol with the given server. Enrolling means sending the server my public key.
// This is sensitive because other users will download the new public key,
// assuming it comes from who it says it comes from. To verify the email address,
// the server will send an encrypted verification email containing a link and a code.
// The user has to enter the code in order to complete enrolment.
//
// On the client side, enrolment happens in two steps. The first step sends a validation
// code to the peer. The second step long-polls until the requested peer becomes active.
// Both steps require a hashcash challenge to be solved.
func (endpoint *Endpoint) enrol() error {

	challengeRequest, err := endpoint.GetChallenge()
	if err != nil {
		return fmt.Errorf("unable to get challenge: %w", err)
	}

	challengeResponse, err := secrt.SolveChallenge(challengeRequest)
	if err != nil {
		return fmt.Errorf("unable to solve challenge: %w", err)
	}

	enrolmentRequest := &secrt.EnrolmentRequest{
		PublicKey: endpoint.PublicKey,
	}

	var header = make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Challenge", base64.StdEncoding.EncodeToString(challengeResponse.Challenge))
	header.Set("Nonce", fmt.Sprintf("%d", challengeResponse.Nonce))

	var enrolmentResponse secrt.EnrolmentResponse
	request := jtp.Request[*secrt.EnrolmentRequest, secrt.EnrolmentResponse]{
		Ctx:     context.Background(),
		Method:  http.MethodPost,
		URL:     endpoint.Path("enrol", endpoint.PeerID),
		Send:    &enrolmentRequest,
		Recv:    &enrolmentResponse,
		Headers: header,
	}

	if err = jtp.DoRequest(&request); err != nil {
		return fmt.Errorf("unable to enrol: %w", err)
	}

	endpoint.ServerKey = enrolmentResponse.ServerKey

	if !enrolmentResponse.Activated {
		fmt.Println(enrolmentResponse.Message)
	}

	return nil
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
