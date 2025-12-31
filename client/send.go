package client

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/commandquery/secrt"
)

// CmdSend sends a secret to a peer.
func CmdSend(config *Config, endpoint *Endpoint, args []string) error {

	flags := flag.NewFlagSet("send", flag.ContinueOnError)
	longFormat := flags.Bool("l", false, "display the full uuid")
	description := flags.String("d", "", "include a description")

	if err := flags.Parse(args); err != nil {
		return err
	}

	args = flags.Args()
	recipient := args[0]

	plaintext, metadata, err := readInput(flags.Args(), 1)
	if err != nil {
		return err
	}

	metadata.Description = *description

	user, err := endpoint.GetPeer(config, recipient)
	if err != nil {
		return fmt.Errorf("unable to get peer: %w", err)
	}

	// Now we have the plaintext message and metadata; we need to encrypt them both into an PrivateKeyEnvelope.
	clearmeta, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("unable to marshal metadata: %w", err)
	}

	envelope := secrt.Envelope{}

	envelope.Metadata, err = endpoint.Encrypt(clearmeta, user.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to encrypt envelope: %w", err)
	}

	envelope.Payload, err = endpoint.Encrypt(plaintext, user.PublicKey)
	if err != nil {
		return fmt.Errorf("unable to encrypt payload: %w", err)
	}

	envelopeJS, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("unable to encode envelope: %w", err)
	}

	if len(envelopeJS) > secrt.MessageSizeLimit {
		return ErrSecretTooBig
	}

	endpointURL := endpoint.URL + "message/" + recipient

	req, err := http.NewRequest("POST", endpointURL, bytes.NewReader(envelopeJS))
	if err != nil {
		return err
	}

	if err = endpoint.SetSignature(req); err != nil {
		return fmt.Errorf("unable to set signature: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("share failed: %s: %s", resp.Status, body)
	}

	var shareResponse secrt.SendResponse
	if err = json.NewDecoder(resp.Body).Decode(&shareResponse); err != nil {
		return fmt.Errorf("unable to decode share response: %w", err)
	}

	if *longFormat {
		fmt.Println(shareResponse.ID.String())
	} else {
		fmt.Println(shareResponse.ID.String()[:8])
	}

	return nil
}
