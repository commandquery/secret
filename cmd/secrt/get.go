package main

import (
	"bytes"
	"crypto/sha256"
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

	claims, err := endpoint.GetClaims(config, message.Claims)
	if err != nil {
		return fmt.Errorf("unable to get claims: %w", err)
	}

	// Verify that the claimed public key matches the published public key
	// for the given peer. The public key is cached, which results in the peer
	// being added to the user's config, if it doesn't already exist.
	// GetPeer is gated by AcceptPeers, so this stops an unknown peer's
	// message from being readable. Note that the "ls" command doesn't do these
	// checks.
	peer, err := endpoint.GetPeer(config, claims.Alias)
	if err != nil {
		return fmt.Errorf("unable to get peer %s: %w", claims.Alias, err)
	}

	if !bytes.Equal(peer.PublicKey, claims.PublicKey) {
		return fmt.Errorf("message claim does not match public key")
	}

	cleartext, err := endpoint.Decrypt(config, claims.PublicKey, message.Payload)
	if err != nil {
		return fmt.Errorf("unable to decrypt message: %w", err)
	}

	// Verify that the claim contains hashes that match the actual payload and metadata.
	// Since the claim is signed by the server but the message data is sent by a peer,
	// this is intended to ensure that server-generated claims can't be replayed.
	payloadHash := sha256.Sum256(message.Payload)
	if !bytes.Equal(payloadHash[:], claims.PayloadHash) {
		return fmt.Errorf("payload claim does not match message payload")
	}

	metadataHash := sha256.Sum256(message.Metadata)
	if !bytes.Equal(metadataHash[:], claims.MetadataHash) {
		return fmt.Errorf("metadata claim does not match message metadata")
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
