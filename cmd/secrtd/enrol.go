package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/google/uuid"
)

func (server *SecretServer) enrolUser(alias string, peerKey []byte) (uuid.UUID, error) {
	// never override an existing peer's public key.
	existingUser, ok := server.GetPeer(alias)
	if ok {
		// peer can re-enrol with their existing public key.
		if bytes.Equal(existingUser.PublicKey, peerKey) {
			return uuid.Nil, nil
		}

		// a new public key requires a reauthentication process which we don't have now.
		return uuid.Nil, ErrExistingPeer
	}

	ctx := context.Background()
	peerID := uuid.New()
	_, err := PGXPool.Exec(ctx, "insert into secrt.peer (server, peer, alias, public_box_key) values ($1, $2, $3, $4)",
		server.Server, peerID, alias, peerKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("unable to enrol user %s: %w", alias, err)
	}

	return peerID, nil
}

// Verify the challenge. If the challenge is invalid, set the HTTP request status and return an error.
func (server *SecretServer) verifyChallenge(w http.ResponseWriter, r *http.Request) error {
	// enrolment requires a challenge and nonce header.
	challenge64 := r.Header.Get("Challenge")
	if challenge64 == "" {
		return WriteStatus(w, http.StatusForbidden, fmt.Errorf("no challenge provided"))
	}

	nonceStr := r.Header.Get("Nonce")
	if nonceStr == "" {
		return WriteStatus(w, http.StatusForbidden, fmt.Errorf("no nonce provided"))
	}

	challenge, err := base64.StdEncoding.DecodeString(challenge64)
	if err != nil {
		return WriteStatus(w, http.StatusBadRequest, fmt.Errorf("invalid challenge encoding: %w", err))
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return WriteStatus(w, http.StatusBadRequest, fmt.Errorf("invalid nonce encoding: %w", err))
	}

	challengeResponse := &secrt.ChallengeResponse{
		Challenge: challenge,
		Nonce:     nonce,
	}

	if err = secrt.ValidateResponse(challengeResponse, server.PublicSignKey); err != nil {
		return WriteStatus(w, http.StatusForbidden, fmt.Errorf("invalid challenge solution: %w", err))
	}

	return nil
}

// Verify enrolment of the user. The actual process used to verify enrolment might change based on the
// server configuration. For example, enrolment may require both a specific domain and an email validation.
func (server *SecretServer) verifyEnrolment(w http.ResponseWriter, r *http.Request) {
	//if err = sendmail(); err != nil {
	//	log.Println("unable to send mail:", err)
	//	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	//	return
	//}

	//if err = pollVerification(); err != nil {
	//	...
	//}
}

// The Enrolment process is straightforward:
// Client requests a hashcash challenge from the server
// Client presents a solution to the server, along with the enrolment request (server ID, peer ID and public key)
// Server creates a record for the peer (status=pending) and returns success (along with its public key).
// Server starts the validation sequence in the background
// Client polls (server ID, peerID, publicKey) until it gets success/failure
// Server processes enrolment request and sets status based on results.

// Enrollment accepts a key from the client, and returns the server key.
func (server *SecretServer) handleEnrol(w http.ResponseWriter, r *http.Request) {

	if err := server.verifyChallenge(w, r); err != nil {
		log.Println(err)
		return
	}

	peerID := r.PathValue("peer")
	log.Printf("challenge response accepted for enrolment request from peer %s", peerID)

	peerKey, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("unable to read peer key:", err)
		_ = WriteStatus(w, http.StatusBadRequest, nil)
		return
	}

	if _, err = server.enrolUser(peerID, peerKey); err != nil {
		if errors.Is(err, ErrExistingPeer) {
			log.Printf("peer %s already enrolled", peerID)
			http.Error(w, "peer already enrolled", http.StatusConflict)
			return
		}

		log.Println("unable to enrol user:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(server.PublicBoxKey)
}
