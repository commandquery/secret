package client

//
// This library contains all the code necessary to parse a user's
// secret configuration (in ~/.config/secret) and extract the
// credentials from that file.
//

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
)

type KeyStoreType string

const (
	KeyStoreClear    KeyStoreType = "clear"
	KeyStorePassword KeyStoreType = "password"
	KeyStorePlatform KeyStoreType = "platform" // Platform keystore. Uses zalando/go-keyring.
)

// Peer contains information about other users.
type Peer struct {
	PeerID    string `json:"peerID"`
	PublicKey []byte `json:"publicKey"`
}

// ConfigVersion is current default version of the configuration file.
const ConfigVersion = 1

// Config represents the client configuration file.
type Config struct {
	Version    int         `json:"version"`   // Config file version
	Endpoints  []*Endpoint `json:"endpoints"` // 0th server is the default server
	Properties *Properties `json:"properties"`

	store    string // Location of secrets store
	modified bool   // indicates that the config changed.
}

// PrivateKeyEnvelope is a concrete envelope around an abstract PrivateKeyStore interface.
type PrivateKeyEnvelope struct {
	Type       KeyStoreType    `json:"type"`       // The dynamic KeyStore type, used for marshal/unmarshal
	Properties json.RawMessage `json:"properties"` // The KeyStore is marshalled into this field.
	keyStore   PrivateKeyStore // The KeyStore is instantiated into this field.
}

// PrivateKeyStore provides a mechanism whereby a private key can be wrapped
// using a variety of methods. This might include storing the private key offboard,
// e.g. via macOS keychain.
//
// Note that there is only a single, canonical private key per endpoint - the key from which the
// public key is derived - but that key can be encoded and stored in multiple ways. To add a new
// encoding (say, touch ID), it's necessary to first use an existing encoding to retreive the underlying key.
type PrivateKeyStore interface {
	Type() KeyStoreType             // Returns the type of this store
	IsUnsealed() bool               // Indicates if the private key has been unsealed.
	Unseal() error                  // Requests that the private key be unsealed.
	GetPrivateKey() ([]byte, error) // Requests the private key material
	Marshal() ([]byte, error)       // Marshal to JSON
	Unmarshal([]byte) error         // Unmarshal to the type.
}

// Endpoint represents a single server as seen from a Client.
// Most of the configuration is specific to the selected server.
type Endpoint struct {
	URL              string                `json:"url"`              // Endpoint URL
	PeerID           string                `json:"peerID"`           // Actual PeerID for this user
	ServerKey        []byte                `json:"serverKey"`        // Public key of this server
	PrivateKeyStores []*PrivateKeyEnvelope `json:"privateKeyStores"` // Set of private keys, in order of user preference.
	PublicKey        []byte                `json:"publicKey"`        // Public key for the private key
	Peers            map[string]*Peer      `json:"peers"`            // Contains info about other users
}

// LoadClientConfig loads the secret configuration, if there is one.
// Returns an empty object (with Stored == false) if no configuration exists.
func LoadClientConfig(store string) (*Config, error) {
	configJS, err := os.ReadFile(store)
	if os.IsNotExist(err) {
		// return an empty, configured object.
		return &Config{
			store:     store,
			modified:  true,
			Version:   ConfigVersion,
			Endpoints: make([]*Endpoint, 0, 1),
			Properties: &Properties{
				AcceptPeers: true,
			}}, nil
	}

	if err != nil {
		return nil, err
	}

	config := Config{store: store}
	err = config.Unmarshal(configJS)
	if err != nil {
		return nil, err
	}

	if config.Version > ConfigVersion {
		return nil, fmt.Errorf("unable to load version %d secrets; please upgrade", config.Version)
	}

	return &config, nil
}

func (config *Config) atomicSave() error {
	contents, err := config.Marshal()
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	dir := filepath.Dir(config.store)

	f, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpName := f.Name()

	// Clean up on any error path
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()

	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}

	if _, err = f.Write(contents); err != nil {
		f.Close()
		return err
	}

	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	if err = os.Rename(tmpName, config.store); err != nil {
		return err
	}

	tmpName = "" // prevent defer from removing
	return nil
}

// Save a secret configuration. This is saved to the location from which it
// was loaded.
func (config *Config) Save() error {

	if !config.modified {
		return nil
	}

	if err := config.atomicSave(); err != nil {
		return fmt.Errorf("could not save config: %v", err)
	}

	return nil
}

// GetFileStore returns the path to the named file.
func (config *Config) GetFileStore(filename string) (string, error) {
	uuname := uuid.NewSHA1(uuid.MustParse("F41E83C3-B3EE-4194-8B0F-5D1932041A86"), []byte(filename)).String()

	// Create the directory if we need to.
	secretStore := config.store + "/files"
	_, err := os.Stat(secretStore)
	if err == nil {
		return secretStore + "/" + uuname, nil
	}

	err = os.MkdirAll(secretStore, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}

	return secretStore + "/" + uuname, nil
}

func NewKeyStore(endpoint *Endpoint, storeType KeyStoreType, privateKey []byte) (PrivateKeyStore, error) {
	switch storeType {
	case KeyStoreClear:
		return NewClearKeyStore(privateKey), nil
	case KeyStorePassword:
		// TODO
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)
	case KeyStorePlatform:
		return NewPlatformKeyStore(endpoint, privateKey)
	default:
		return nil, fmt.Errorf("unsupported key store type: %s", storeType)

	}
}

// GetEndpoint returns any existing endpoint for the given (peerID, serverURL) pair.
func (config *Config) GetEndpoint(peerID, serverURL string) *Endpoint {
	for _, endpoint := range config.Endpoints {
		if endpoint.URL == serverURL && endpoint.PeerID == peerID {
			return endpoint
		}
	}

	return nil
}

// DeleteEndpoint deletes any existing endpoint for the given (peerID, serverURL) pair.
func (config *Config) DeleteEndpoint(peerID, endpointURL string) {
	config.Endpoints = slices.DeleteFunc(config.Endpoints, func(e *Endpoint) bool {
		return e.URL == endpointURL && e.PeerID == peerID
	})
	config.modified = true
}

// AddEndpoint adds a new server to the config, and generates a new, cleartext keypair for that server.
// This function will only replace an existing endpoint for the given (peerID, endpointURL) if force is true.
func (config *Config) AddEndpoint(peerID, endpointURL string, storeType KeyStoreType, force bool) error {

	// Check if there's an existing enrolment; abort if force isn't set.
	existingEndpoint := config.GetEndpoint(peerID, endpointURL)
	if existingEndpoint != nil {
		if !force {
			return ErrExistingEnrolment
		}

		config.DeleteEndpoint(peerID, endpointURL)
	}

	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(endpointURL, "/") {
		endpointURL += "/"
	}

	newEndpoint := &Endpoint{
		URL:       endpointURL,
		PeerID:    peerID,
		PublicKey: public[:],
		Peers:     make(map[string]*Peer),
	}

	keyStore, err := NewKeyStore(newEndpoint, storeType, private[:])
	if err != nil {
		return err
	}

	newEndpoint.PrivateKeyStores = []*PrivateKeyEnvelope{
		{Type: storeType, keyStore: keyStore},
	}

	err = newEndpoint.enrol()
	if err != nil {
		return fmt.Errorf("unable to enrol user at %s: %w", endpointURL, err)
	}

	config.Endpoints = append(config.Endpoints, newEndpoint)
	config.modified = true

	return nil
}

// Set a property. The expression is of the form "property=value".
func (config *Config) Set(expression string) error {
	namevalue := strings.Split(expression, "=")
	if len(namevalue) != 2 {
		return fmt.Errorf("invalid expression: %s", expression)
	}

	if err := config.Properties.Set(namevalue[0], namevalue[1]); err != nil {
		return fmt.Errorf("unable to set %s: %w", namevalue[0], err)
	}

	config.modified = true

	return nil
}

// Marshal returns the JSON representation of the config. Before marshalling, it updates the
// KeyStore JSON representation, which enables load/save of the underlying interface data.
func (config *Config) Marshal() ([]byte, error) {
	var err error

	for _, server := range config.Endpoints {
		for _, key := range server.PrivateKeyStores {
			key.Properties, err = key.keyStore.Marshal()
			if err != nil {
				return nil, err
			}
		}
	}

	return json.MarshalIndent(config, "", "  ")
}

// Unmarshal reads JSON and updates the associated config. As part of the unmarshalling process,
// it creates concrete KeyStore instances (PrivateKeyStore interface) based on the PrivateKeyEnvelope
// types.
func (config *Config) Unmarshal(data []byte) error {
	err := json.Unmarshal(data, config)
	if err != nil {
		return fmt.Errorf("unable to parse config: %w", err)
	}

	for _, server := range config.Endpoints {
		for _, key := range server.PrivateKeyStores {
			switch key.Type {
			case KeyStoreClear:
				ks := &ClearKeyStore{}
				err = ks.Unmarshal(key.Properties)
				if err != nil {
					return err
				}

				key.keyStore = ks

			case KeyStorePlatform:
				ks := &PlatformKeyStore{}
				err = ks.Unmarshal(key.Properties)
				if err != nil {
					return err
				}

				key.keyStore = ks
			}
		}
	}

	return nil
}
