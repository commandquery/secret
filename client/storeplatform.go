package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/zalando/go-keyring"
)

type PlatformKeyStore struct {
	Service    string `json:"service"` // Always "secrt.io"
	User       string `json:"user"`    // Always the URL of the endpoint
	privateKey []byte // Cached (unsealed) private key, never marshalled/unmarshalled
}

func NewPlatformKeyStore(endpoint *Endpoint, privateKey []byte) (*PlatformKeyStore, error) {

	key64 := base64.StdEncoding.EncodeToString(privateKey)

	keystore := &PlatformKeyStore{
		Service:    "secrt.io",
		User:       endpoint.URL,
		privateKey: privateKey,
	}

	err := keyring.Set(keystore.Service, keystore.User, key64)
	if err != nil {
		return nil, fmt.Errorf("unable to save key to platform store: %w", err)
	}

	return keystore, nil
}

func (s *PlatformKeyStore) Type() KeyStoreType {
	return KeyStorePlatform
}

func (s *PlatformKeyStore) IsUnsealed() bool {
	return s.privateKey != nil
}

func (s *PlatformKeyStore) Unseal() error {
	secret, err := keyring.Get(s.Service, s.User)
	if err != nil {
		return fmt.Errorf("unable to get secret from platform store: %w", err)
	}

	s.privateKey, err = base64.StdEncoding.DecodeString(secret)
	return err
}

func (s *PlatformKeyStore) GetPrivateKey() ([]byte, error) {
	if s.privateKey == nil {
		return nil, fmt.Errorf("private key is not initialized")
	}
	return s.privateKey, nil
}

func (s *PlatformKeyStore) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *PlatformKeyStore) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
