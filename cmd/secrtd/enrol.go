package main

import (
	"bytes"
	"context"
	"encoding/base64"
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
func (server *SecretServer) verifyChallenge(r *http.Request) error {
	// enrolment requires a challenge and nonce header.
	challenge64 := r.Header.Get("Challenge")
	if challenge64 == "" {
		return ErrForbidden(fmt.Errorf("no challenge provided"))
	}

	nonceStr := r.Header.Get("Nonce")
	if nonceStr == "" {
		return ErrForbidden(fmt.Errorf("no nonce provided"))
	}

	challenge, err := base64.StdEncoding.DecodeString(challenge64)
	if err != nil {
		return ErrBadRequest(fmt.Errorf("invalid challenge encoding: %w", err))
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return ErrBadRequest(fmt.Errorf("invalid nonce encoding: %w", err))
	}

	challengeResponse := &secrt.ChallengeResponse{
		Challenge: challenge,
		Nonce:     nonce,
	}

	if err = secrt.ValidateResponse(challengeResponse, server.PublicSignKey); err != nil {
		return ErrForbidden(fmt.Errorf("invalid challenge solution: %w", err))
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
func (server *SecretServer) handleEnrol(ctx context.Context, req *secrt.EnrolmentRequest) (*secrt.EnrolmentResponse, *HTTPError) {

	r := GetRequest(ctx)

	if err := server.verifyChallenge(r); err != nil {
		return nil, ErrForbidden(err)
	}

	peerID := r.PathValue("peer")
	log.Printf("challenge response accepted for enrolment request from peer %s", peerID)

	enrolmentUrl, code, err := server.makeEnrolmentURL(GetHostname(r), peerID, req.PublicKey)
	if err != nil {
		return nil, ErrInternalServerError(err)
	}

	log.Println("url:", enrolmentUrl)
	log.Println("code:", code)

	if _, err := server.enrolUser(peerID, req.PublicKey); err != nil {
		if errors.Is(err, ErrExistingPeer) {
			return nil, ErrConflict(fmt.Errorf("peer %s already enrolled", peerID))
		}

		return nil, ErrInternalServerError(err)
	}

	return &secrt.EnrolmentResponse{
		ServerKey: server.PublicBoxKey,
	}, nil
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

func (server *SecretServer) handleValidate(ctx context.Context, req *secrt.ValidationRequest) (*secrt.ValidationResponse, *HTTPError) {
	sealedToken, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, ErrBadRequest(err)
	}

	enrolmentToken, err := decrypt[EnrolmentToken](server, sealedToken)
	if err != nil {
		return nil, ErrBadRequest(err)
	}

	if req.Code != enrolmentToken.Code {
		return nil, ErrForbidden(fmt.Errorf("enrolment token code does not match request"))
	}

	log.Println("got valid enrolment request for", enrolmentToken.Peer)

	return &secrt.ValidationResponse{}, nil
}
