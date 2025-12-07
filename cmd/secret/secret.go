package main

//
// This library contains all the code necessary to parse a user's
// secret configuration (in ~/.config/secret) and extract the
// credentials from that file.
//

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

var DefaultSecretLocation = os.Getenv("SECRETS_DIR")

// Peer contains information about other users.
type Peer struct {
	PeerID    string `json:"peerID"`
	PublicKey []byte `json:"publicKey"`
}

// ConfigVersion is current default version of the configuration file.
const ConfigVersion = 1

// Client represents the client configuration file.
type Client struct {
	Version       int         `json:"version"`       // Config file version
	DefaultPeerID string      `json:"defaultPeerID"` // Default peer ID
	Store         string      `json:"-"`             // Location of secrets store
	Stored        bool        `json:"-"`             // Indicates if the config came from disk (not in JSON)
	Servers       []*Endpoint `json:"servers"`       // 0th server is the default server
}

// Endpoint represents a single server as seen from a Client.
// Most of the configuration is specific to the selected server.
type Endpoint struct {
	URL        string           `json:"url"`        // Endpoint URL
	PeerID     string           `json:"peerID"`     // Actual PeerID for this user
	ServerKey  []byte           `json:"serverKey"`  // Public key of this server
	PrivateKey []byte           `json:"privateKey"` // Private key, encrypted with user's password
	PublicKey  []byte           `json:"publicKey"`  // Public key for the private key
	Peers      map[string]*Peer `json:"peers"`      // Contains info about other users
}

// To32 converts a slice to a 32 byte array for use with nacl.
func To32(bytes []byte) *[32]byte {
	var result [32]byte
	if copy(result[:], bytes) != 32 {
		panic(fmt.Errorf("Attempted to create non-32 bit key"))
	}

	return &result
}

// LoadSecretConfiguration loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadSecretConfiguration(store string) (*Client, error) {
	secretFile := store + "/keys"
	secretContents, err := os.ReadFile(secretFile)
	if os.IsNotExist(err) {
		// return an empty object.
		return &Client{Version: ConfigVersion, Stored: false, Store: store}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Client{Stored: true, Store: store}
	err = json.Unmarshal(secretContents, &config)
	if err != nil {
		return nil, err
	}

	if config.Version > ConfigVersion {
		return nil, fmt.Errorf("unable to load version %d secrets; please upgrade", config.Version)
	}

	return &config, nil
}

// Save a secret configuration. This is saved to the location from which it
// was loaded.
func (config *Client) Save() error {
	secretFile := config.Store + "/keys"
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	contents = append(contents, '\n')

	err = os.WriteFile(secretFile, contents, 0600)
	return err
}

// GetSecretStore returns the filename where the secret configuration is stored.
func GetSecretStore() (string, error) {
	secretDirectory := DefaultSecretLocation
	if secretDirectory != "" {
		return secretDirectory, nil
	}

	home, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	secretDirectory = filepath.Join(home, "secret")
	err = os.MkdirAll(secretDirectory, 0700)
	if err != nil {
		return "", err
	}

	return secretDirectory, nil
}

// GetFileStore returns the path to the named file.
func (config *Client) GetFileStore(filename string) (string, error) {
	uuname := uuid.NewSHA1(uuid.MustParse("F41E83C3-B3EE-4194-8B0F-5D1932041A86"), []byte(filename)).String()

	// Create the directory if we need to.
	secretStore := config.Store + "/files"
	_, err := os.Stat(secretStore)
	if err == nil {
		return secretStore + "/" + uuname, nil
	}

	err = os.MkdirAll(secretStore, 0700)
	if err != nil && err != os.ErrExist {
		return "", err
	}

	return secretStore + "/" + uuname, nil
}

// Enrol with the given server. Enrolling means the server knows about
// me, and I know the server's public key.
func (endpoint *Endpoint) enrol() error {
	u, err := url.Parse(endpoint.URL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}
	u.Path = path.Join(u.Path, "enrol", url.PathEscape(endpoint.PeerID))

	// Post my public key
	resp, err := http.Post(u.String(), "application/octet-stream", bytes.NewReader(endpoint.PublicKey))
	if err != nil {
		return fmt.Errorf("unable to enrol: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status from server: %s", resp.Status)
	}

	serverKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read server key: %w", err)
	}

	endpoint.ServerKey = serverKey
	return nil
}

// AddServer adds a new server to the config, and generates a new keypair for that server.
func (config *Client) AddServer(serverURL string) error {

	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	server := &Endpoint{
		URL:        serverURL,
		PeerID:     config.DefaultPeerID,
		PrivateKey: private[:],
		PublicKey:  public[:],
		Peers:      make(map[string]*Peer),
	}

	err = server.enrol()
	if err != nil {
		return fmt.Errorf("unable to fetch key from server %s: %w", serverURL, err)
	}

	config.Servers = append(config.Servers, server)
	return nil
}
