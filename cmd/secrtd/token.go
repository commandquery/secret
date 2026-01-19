package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"

	"github.com/commandquery/secrt"
	"golang.org/x/crypto/nacl/secretbox"
)

type EnrolmentToken struct {
	Peer      string `json:"p"`
	PublicKey []byte `json:"k"`
	Code      int    `json:"c"` // code that must be entered into the verify page
}

func encrypt[T any](server *SecretServer, v *T) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(v); err != nil {
		return nil, err
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	sealed := secretbox.Seal(nonce[:], buf.Bytes(), &nonce, secrt.To32(server.SecretBoxKey))
	return sealed, nil
}

func decrypt[T any](server *SecretServer, sealed []byte) (*T, error) {

	if len(sealed) < 24 {
		return nil, errors.New("invalid token")
	}

	var nonce [24]byte
	copy(nonce[:], sealed[:24])

	plaintext, ok := secretbox.Open(nil, sealed[24:], &nonce, secrt.To32(server.SecretBoxKey))
	if !ok {
		return nil, errors.New("decryption failed")
	}

	var v T
	if err := gob.NewDecoder(bytes.NewReader(plaintext)).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
