package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"regexp"

	"github.com/commandquery/secrt"
)

var peerRegexp = regexp.MustCompile(`^[^@\s\\]+@[^@\s]+\.[^@\s]+$`)

// CmdSend sends a secret to a peer.
func CmdSend(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("send", flag.ContinueOnError)
	description := flags.String("d", "", "include a description")

	if err := flags.Parse(args); err != nil {
		return err
	}

	var peerList []string
	var selectedFile string

	// Extract all the peer IDs from the arguments.
	for _, arg := range flags.Args() {
		if peerRegexp.MatchString(arg) {
			peerList = append(peerList, arg)
		} else {
			if selectedFile != "" {
				return fmt.Errorf("at most one file can be specified")
			}
			selectedFile = arg
		}
	}

	if len(peerList) == 0 {
		return fmt.Errorf("no peers specified")
	}

	plaintext, metadata, err := readInput(selectedFile)
	if err != nil {
		return err
	}

	metadata.Description = *description

	// Do a pass to ensure that all peers are known. This lets us fail early if we don't
	// accept new peers, or if there's a typo.
	for _, peerID := range peerList {
		_, err = endpoint.GetPeer(config, peerID)
		if err != nil {
			return fmt.Errorf("unable to get peer: %w", err)
		}
	}

	// Now we have the plaintext message and metadata; we need to encrypt them both into an PrivateKeyEnvelope.
	clearmeta, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("unable to marshal metadata: %w", err)
	}

	// Now do another pass that actually sends the message.
	var sendErrors []error
	var sendRequests []secrt.SendRequest

	for _, peerID := range peerList {
		peer, err := endpoint.GetPeer(config, peerID)
		if err != nil {
			return fmt.Errorf("unable to get peer: %w", err)
		}

		request := secrt.SendRequest{}

		request.Metadata, err = endpoint.Encrypt(clearmeta, peer.PublicKey)
		if err != nil {
			return fmt.Errorf("unable to encrypt metadata: %w", err)
		}

		request.Payload, err = endpoint.Encrypt(plaintext, peer.PublicKey)
		if err != nil {
			return fmt.Errorf("unable to encrypt payload: %w", err)
		}

		sendRequests = append(sendRequests, request)
	}

	for i, request := range sendRequests {
		var sendResponse secrt.SendResponse

		err = Call(endpoint, request, &sendResponse, "POST", "message", peerList[i])
		if err != nil {
			sendErrors = append(sendErrors, err)
		} else {
			fmt.Printf("%s\n", sendResponse.ID.String())
		}
	}

	return errors.Join(sendErrors...)
}
