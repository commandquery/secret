package secrt

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/sign"
)

func TestChallenge(t *testing.T) {
	publicSignKey, privateSignKey, err := sign.GenerateKey(rand.Reader)

	challengeRequest, err := NewChallenge(20, privateSignKey[:])
	if err != nil {
		t.Fatal(err)
	}

	challengeResponse, err := SolveChallenge(challengeRequest)
	if err != nil {
		t.Fatal(err)
	}

	err = ValidateResponse(challengeResponse, publicSignKey[:])
	if err != nil {
		t.Fatal(err)
	}
}
