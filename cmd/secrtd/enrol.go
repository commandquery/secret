package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

func (server *SecretServer) enrolUser(alias string, peerKey []byte) error {
	// never override an existing peer's public key.
	existingUser, ok := server.GetPeer(alias)
	if ok {
		// peer can re-enrol with their existing public key.
		if bytes.Equal(existingUser.PublicKey, peerKey) {
			return nil
		}

		// a new public key requires a reauthentication process which we don't have now.
		//return uuid.Nil, ErrExistingPeer
		return jtp.ConflictError(ErrExistingPeer)
	}

	ctx := context.Background()
	peerID := uuid.New()
	_, err := PGXPool.Exec(ctx, "insert into secrt.peer (server, peer, alias, public_box_key) values ($1, $2, $3, $4)",
		server.Server, peerID, alias, peerKey)
	if err != nil {
		return jtp.InternalServerError(fmt.Errorf("unable to enrol user %s: %w", alias, err))
	}

	return nil
}

// Verify the challenge. If the challenge is invalid, set the HTTP request status and return an error.
func (server *SecretServer) verifyChallenge(r *http.Request) error {
	// enrolment requires a challenge and nonce header.
	challenge64 := r.Header.Get("Challenge")
	if challenge64 == "" {
		return jtp.ForbiddenError(fmt.Errorf("no challenge provided"))
	}

	nonceStr := r.Header.Get("Nonce")
	if nonceStr == "" {
		return jtp.ForbiddenError(fmt.Errorf("no nonce provided"))
	}

	challenge, err := base64.StdEncoding.DecodeString(challenge64)
	if err != nil {
		return jtp.BadRequestError(fmt.Errorf("invalid challenge encoding: %w", err))
	}

	nonce, err := strconv.ParseUint(nonceStr, 10, 64)
	if err != nil {
		return jtp.BadRequestError(fmt.Errorf("invalid nonce encoding: %w", err))
	}

	challengeResponse := &secrt.ChallengeResponse{
		Challenge: challenge,
		Nonce:     nonce,
	}

	if err = secrt.ValidateResponse(challengeResponse, server.PublicSignKey); err != nil {
		return jtp.ForbiddenError(fmt.Errorf("invalid challenge solution: %w", err))
	}

	return nil
}

type ActivationToken struct {
	Peer  string
	Token string
	Code  int
}

func (server *SecretServer) sendActivationToken(token *ActivationToken) error {
	log.Println("sending token:", token.Token)
	log.Println("activation code:", token.Code)

	switch Config.EnrolAction {
	case EnrolMail:
		// Queue the email up
		ActivateMailChannel <- token
	case EnrolFile:
		// File is used only in testing.
		f, err := os.OpenFile(Config.EnrolFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Println("error opening enrolment file:", err)
		}

		defer f.Close()

		_, err = fmt.Fprintf(f, "%s %06d\n", token.Token, token.Code)
		if err != nil {
			log.Println("error writing to enrolment file:", err)
		}
	}

	return nil
}

// Enrollment accepts a key from the client, and returns the server key.
func (server *SecretServer) handleEnrol(r *http.Request, req *secrt.EnrolmentRequest) (*secrt.EnrolmentResponse, error) {

	if err := server.verifyChallenge(r); err != nil {
		return nil, jtp.ForbiddenError(err)
	}

	peerID := r.PathValue("peer")
	log.Printf("challenge response accepted for enrolment request from peer %s", peerID)

	// EnrolAction is only enabled for testing. It's never enabled in production.
	if Config.EnrolAction == EnrolAuto {
		if err := server.enrolUser(peerID, req.PublicKey); err != nil {
			return nil, err
		}

		return &secrt.EnrolmentResponse{
			ServerKey: server.PublicBoxKey,
			Activated: true,
		}, nil
	}

	token, err := server.makeActivationToken(peerID, req.PublicKey)
	if err != nil {
		return nil, jtp.InternalServerError(err)
	}

	if err = server.sendActivationToken(token); err != nil {
		return nil, jtp.InternalServerError(err)
	}

	return &secrt.EnrolmentResponse{
		ServerKey: server.PublicBoxKey,
		Activated: false,
	}, nil
}

// Encode the enrolment details into a URL. Note that we use URLEncoding for this.
func (server *SecretServer) makeActivationToken(alias string, publicKey []byte) (*ActivationToken, error) {
	enrolmentToken := &EnrolmentToken{
		Peer:      alias,
		PublicKey: publicKey,
		Code:      rand.IntN(999999) + 1,
	}

	sealedToken, err := encrypt(server, enrolmentToken)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt enrolment token: %v", err)
	}

	return &ActivationToken{
		Peer:  alias,
		Token: base64.URLEncoding.EncodeToString(sealedToken),
		Code:  enrolmentToken.Code,
	}, nil
}

func (server *SecretServer) handleActivate(r *http.Request, req *secrt.ActivationRequest) (*secrt.ActivationResponse, error) {
	sealedToken, err := base64.URLEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, jtp.BadRequestError(err)
	}

	enrolmentToken, err := decrypt[EnrolmentToken](server, sealedToken)
	if err != nil {
		return nil, jtp.BadRequestError(err)
	}

	if req.Code != enrolmentToken.Code {
		return nil, jtp.ForbiddenError(fmt.Errorf("enrolment token code does not match request"))
	}

	log.Println("got valid activation request for", enrolmentToken.Peer)

	if err := server.enrolUser(enrolmentToken.Peer, enrolmentToken.PublicKey); err != nil {
		return nil, err
	}

	return &secrt.ActivationResponse{
		Message: "Welcome to secrt!",
	}, nil
}
