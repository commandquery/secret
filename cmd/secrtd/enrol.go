package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
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
		LogError(w, http.StatusUnauthorized, err)
		return
	}

	peerID := r.PathValue("peer")
	log.Printf("challenge response accepted for enrolment request from peer %s", peerID)

	var enrolmentRequest secrt.EnrolmentRequest
	if err := json.NewDecoder(r.Body).Decode(&enrolmentRequest); err != nil {
		LogError(w, http.StatusBadRequest, err)
		return
	}

	enrolmentUrl, code, err := server.makeEnrolmentURL(GetHostname(r), peerID, enrolmentRequest.PublicKey)
	if err != nil {
		LogError(w, http.StatusInternalServerError, err)
		return
	}

	log.Println("url:", enrolmentUrl)
	log.Println("code:", code)

	if _, err := server.enrolUser(peerID, enrolmentRequest.PublicKey); err != nil {
		if errors.Is(err, ErrExistingPeer) {
			LogError(w, http.StatusConflict, fmt.Errorf("peer %s already enrolled", peerID))
			return
		}

		LogError(w, http.StatusInternalServerError, err)

		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(server.PublicBoxKey)
}

// Encode the enrolment details into a URL. Note that we use URLEncoding for this.
func (server *SecretServer) makeEnrolmentURL(hostname string, alias string, publicKey []byte) (string, int, error) {
	enrolmentToken := &EnrolmentToken{
		Peer:      alias,
		PublicKey: publicKey,
		Code:      rand.IntN(999999) + 1,
	}

	sealedToken, err := encrypt(server, enrolmentToken)
	if err != nil {
		return "", 0, fmt.Errorf("failed to encrypt enrolment token: %v", err)
	}

	return "https://" + hostname + "/validate/?t=" + base64.URLEncoding.EncodeToString(sealedToken), enrolmentToken.Code, nil
}

func (server *SecretServer) handleValidate(w http.ResponseWriter, r *http.Request) {
	var validationRequest secrt.ValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&validationRequest); err != nil {
		LogError(w, http.StatusBadRequest, err)
		return
	}

	sealedToken, err := base64.URLEncoding.DecodeString(validationRequest.Token)
	if err != nil {
		LogError(w, http.StatusBadRequest, err)
		return
	}

	enrolmentToken, err := decrypt[EnrolmentToken](server, sealedToken)
	if err != nil {
		LogError(w, http.StatusBadRequest, err)
		return
	}

	if validationRequest.Code != enrolmentToken.Code {
		LogError(w, http.StatusForbidden, fmt.Errorf("invalid enrolment token code"))
		return
	}

	log.Println("got valid enrolment request for", enrolmentToken.Peer)
}
