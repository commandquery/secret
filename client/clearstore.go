package client

import (
	"encoding/json"
)

type ClearKeyStore struct {
	PrivateKey []byte `json:"privateKey"`
}

func (s *ClearKeyStore) Type() KeyStoreType {
	return KeyStoreClear
}

func (s *ClearKeyStore) IsUnsealed() bool {
	return true
}

func (s *ClearKeyStore) Unseal() error {
	return nil
}

func (s *ClearKeyStore) GetPrivateKey() ([]byte, error) {
	return s.PrivateKey, nil
}

func (s *ClearKeyStore) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func (s *ClearKeyStore) Unmarshal(bytes []byte) error {
	return json.Unmarshal(bytes, s)
}
