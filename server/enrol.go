package server

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) enrolUser(peerID string, peerKey []byte) error {
	// never override an existing user's public key.
	existingUser, ok := server.GetUser(peerID)
	if ok {
		// user can re-enrol with their existing public key.
		if bytes.Equal(existingUser.PublicKey, peerKey) {
			return nil
		}

		// a new public key requires a reauthentication process which we don't have now.
		return ErrExistingPeer
	}

	user := &Peer{
		PeerID:    peerID,
		PublicKey: peerKey,
	}

	server.Peers[peerID] = user

	if err := server.Save(); err != nil {
		return fmt.Errorf("unable to enrol user: %w", err)
	}

	return nil
}

// Enrollment accepts a key from the client, and returns the server key.
func (server *SecretServer) handleEnrol(w http.ResponseWriter, r *http.Request) {

	if server.AutoEnrol == "false" {
		http.Error(w, "Enrolment disabled", http.StatusForbidden)
		return
	}

	// enrolment requires a challenge and nonce header.
	challenge64 := r.Header.Get("Challenge")
	if challenge64 == "" {
		log.Println("no challenge provided")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	nonceStr := r.Header.Get("Nonce")
	if nonceStr == "" {
		log.Println("no nonce provided")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	challenge, err := base64.StdEncoding.DecodeString(challenge64)
	if err != nil {
		log.Printf("invalid challenge encoding: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		log.Printf("invalid nonce encoding: %v", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	challengeResponse := &secrt.ChallengeResponse{
		Challenge: challenge,
		Nonce:     nonce,
	}

	if err = secrt.ValidateResponse(challengeResponse, server.PublicSignKey); err != nil {
		log.Printf("invalid challenge solution: %v", err)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	server.lock.Lock()
	defer server.lock.Unlock()

	peerID := r.PathValue("peer")
	log.Printf("accepted enrol request with nonce %d for peer %s", challengeResponse.Nonce, peerID)

	peerKey, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("unable to read peer key:", err)
		http.Error(w, "unable to read peer key", http.StatusBadRequest)
		return
	}

	if server.AutoEnrol == "approve" {
		log.Printf("approval requested for peer %s %s", peerID, base64.StdEncoding.EncodeToString(peerKey))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(server.PublicBoxKey)
		return
	}

	if err = server.enrolUser(peerID, peerKey); err != nil {
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
