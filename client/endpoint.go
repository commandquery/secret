package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/commandquery/secrt"
	"golang.org/x/crypto/nacl/box"
)

var ErrUnknownPeer error = errors.New("unknown peer")
var ErrExistingEnrolment error = errors.New("already enrolled")
var ErrSecretTooBig error = errors.New("secret too big")

// Path returns a path URL relative to the endpoint.
func (endpoint *Endpoint) Path(path ...string) string {
	var urlPath strings.Builder

	for i, p := range path {
		if i > 0 {
			urlPath.WriteRune('/')
		}
		urlPath.WriteString(url.PathEscape(p))
	}

	// note that endpoint URL must always end in "/".
	return endpoint.URL + urlPath.String()
}

// GetPeer returns the public key for a given peer (if known).
func (endpoint *Endpoint) GetPeer(config *Config, peerId string) (*Peer, error) {
	if endpoint.Peers != nil {
		entry, ok := endpoint.Peers[peerId]
		if ok {
			return entry, nil
		}
	}

	if !config.Properties.AcceptPeers {
		return nil, fmt.Errorf("%w: %s", ErrUnknownPeer, peerId)
	}

	newPeer, err := endpoint.AddPeer(peerId)
	if err != nil {
		return nil, fmt.Errorf("unable to add peer: %w", err)
	}

	config.modified = true
	return newPeer, nil
}

func (endpoint *Endpoint) AddPeer(peerId string) (*Peer, error) {

	endpointURL := endpoint.Path("peer", peerId)

	req, err := http.NewRequest("GET", endpointURL, nil)
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %w", err)
	}

	if err = endpoint.SetSignature(req); err != nil {
		return nil, fmt.Errorf("unable to set signature: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to contact server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("peer %s not found", peerId)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer request failed: %s: %s", resp.Status, body)
	}

	peerjs, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read peer: %w", err)
	}

	var peerResp secrt.Peer
	if err = json.Unmarshal(peerjs, &peerResp); err != nil {
		return nil, fmt.Errorf("unable to unmarshal peer: %w", err)
	}

	if len(peerResp.PublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d", len(peerResp.PublicKey))
	}

	if peerResp.Peer != peerId {
		return nil, fmt.Errorf("received wrong peer id: %s (expected %s)", peerResp.Peer, peerId)
	}

	// Write this to stderr so stdout isn't affected.
	_, _ = fmt.Fprintln(os.Stderr, "Adding new peer", peerId)
	peer := &Peer{
		PeerID:    peerId,
		PublicKey: peerResp.PublicKey,
	}

	endpoint.Peers[peerId] = peer
	return peer, nil
}

// SetSignature returns a Signature header, which is just the peer ID
// followed by the current timestamp, encrypted for the server itself.
// This authenticates us to the server within the request header, giving
// us strong access control without a handshake.
func (endpoint *Endpoint) SetSignature(req *http.Request) error {
	msg := fmt.Sprintf("%d", time.Now().Unix())

	ciphertext, err := endpoint.Encrypt([]byte(msg), endpoint.ServerKey)
	if err != nil {
		return fmt.Errorf("unable to generate signature: %w", err)
	}

	// entire signature is json encoded to avoid issues with little bobby table's peer ID.
	signature := &secrt.Signature{
		Peer: endpoint.PeerID,
		Sig:  ciphertext,
	}

	js, err := json.Marshal(signature)
	if err != nil {
		return fmt.Errorf("unable to marshal signature: %w", err)
	}

	req.Header.Set("Signature", base64.StdEncoding.EncodeToString(js))
	return nil
}

// readInput reads a byte slice from a file or stdin. If the filename is "", read from stdin.
// Returns the byte array as well as file metadata.
func readInput(filename string) ([]byte, *secrt.Metadata, error) {
	metadata := &secrt.Metadata{}

	// Use a filename, or just stdin?
	var reader io.Reader
	if filename != "" {
		file, err := os.Open(filename)
		if err != nil {
			return nil, nil, err
		}

		defer file.Close()
		metadata.Filename = filepath.Base(file.Name())
		reader = file
	} else {
		metadata.Filename = ""
		reader = os.Stdin
	}

	cleartext, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}

	metadata.Size = len(cleartext)
	return cleartext, metadata, nil
}

func (endpoint *Endpoint) GetPrivateKey() ([]byte, error) {
	if len(endpoint.PrivateKeyStores) == 0 {
		return nil, fmt.Errorf("no private key store found")
	}

	// Try to find an unsealed key.
	for _, key := range endpoint.PrivateKeyStores {
		if key.keyStore != nil {
			if key.keyStore.IsUnsealed() {
				return key.keyStore.GetPrivateKey()
			}
		}
	}

	// Try to unseal the first key.
	envelope := endpoint.PrivateKeyStores[0]

	if envelope.keyStore != nil {
		if err := envelope.keyStore.Unseal(); err != nil {
			return nil, fmt.Errorf("unable to unseal private key: %w", err)
		}

		return envelope.keyStore.GetPrivateKey()
	}

	return nil, fmt.Errorf("no private key found")
}

func (endpoint *Endpoint) Encrypt(plaintext []byte, peerKey []byte) ([]byte, error) {
	// You must use a different nonce for each message you encrypt with the
	// same key. Since the nonce here is 192 bits long, a random value
	// provides a sufficiently small probability of collisions.
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("unable to generate nonce: %w", err)
	}

	// Prefix the message with a version number of the ciphertext message.
	// Current version is zero.
	var ciphertext = []byte{0}

	// Append the nonce, which is a fixed length (24 bytes).
	ciphertext = append(ciphertext, nonce[:]...)

	privateKey, err := endpoint.GetPrivateKey()
	if err != nil {
		return nil, err
	}

	// Encrypt the message itself and append to the nonce + public key
	return box.Seal(ciphertext, plaintext, &nonce, secrt.To32(peerKey), secrt.To32(privateKey)), nil
}

func (endpoint *Endpoint) Decrypt(config *Config, peerID string, ciphertext []byte) ([]byte, error) {
	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`", ciphertext[0])
	}

	peer, err := endpoint.GetPeer(config, peerID)
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	privateKey, err := endpoint.GetPrivateKey()
	if err != nil {
		return nil, err
	}

	var out []byte
	out, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peer.PublicKey), secrt.To32(privateKey))

	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peerID)
	}

	return out, nil
}

func (endpoint *Endpoint) GetChallenge() (*secrt.ChallengeRequest, error) {
	endpointURL := endpoint.Path("challenge")
	resp, err := http.Get(endpointURL)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var challenge *secrt.ChallengeRequest
	if err := json.Unmarshal(body, &challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}

// Enrol with the given server. Enrolling means the server knows about
// me, and I know the server's public key.
// Note that enrolment is the only API that doesn't require a signature, so the
// structure of this client code is unique.
//
// TODO: should require HashCash to enrol.
func (endpoint *Endpoint) enrol() error {

	challengeRequest, err := endpoint.GetChallenge()
	if err != nil {
		return fmt.Errorf("unable to get challenge: %w", err)
	}

	challengeResponse, err := secrt.SolveChallenge(challengeRequest)
	if err != nil {
		return fmt.Errorf("unable to solve challenge: %w", err)
	}

	endpointURL := endpoint.Path("enrol", endpoint.PeerID)

	// Post my public key
	req, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewReader(endpoint.PublicKey))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Challenge", base64.StdEncoding.EncodeToString(challengeResponse.Challenge))
	req.Header.Set("Nonce", fmt.Sprintf("%d", challengeResponse.Nonce))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("unable to enrol: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("enrolment completed")
	case http.StatusAccepted:
		fmt.Println("enrolment requested")
	case http.StatusConflict:
		return fmt.Errorf("user already enrolled")
	default:
		return fmt.Errorf("unexpected status from server: %s", resp.Status)
	}

	serverKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read server key: %w", err)
	}

	endpoint.ServerKey = serverKey
	return nil
}
