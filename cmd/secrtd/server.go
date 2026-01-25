package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
)

var ErrExistingPeer error = errors.New("peer already exists")
var ErrAmbiguousMessageID error = errors.New("ambiguous message ID")
var ErrUnknownMessageID error = errors.New("unknown message ID")

type SecretServer struct {
	Server         uuid.UUID
	Hostname       string
	SecretBoxKey   []byte
	PrivateBoxKey  []byte
	PublicBoxKey   []byte
	PrivateSignKey []byte
	PublicSignKey  []byte
}

// NewSecretServer returns a new SecretServer with a unique private and public key.
func NewSecretServer(hostname string) *SecretServer {
	publicBoxKey, privateBoxKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	publicSignKey, privateSignKey, err := sign.GenerateKey(rand.Reader)
	var secretBoxKey [32]byte
	if _, err := rand.Read(secretBoxKey[:]); err != nil {
		panic(err)
	}

	server := &SecretServer{
		Server:         uuid.New(),
		Hostname:       hostname,
		SecretBoxKey:   secretBoxKey[:],
		PrivateBoxKey:  privateBoxKey[:],
		PublicBoxKey:   publicBoxKey[:],
		PrivateSignKey: privateSignKey[:],
		PublicSignKey:  publicSignKey[:],
	}

	return server
}

// GetSecretServer returns a secret server based on the given hostname.
func GetSecretServer(hostname string) (*SecretServer, error) {
	ctx := context.Background()
	row := PGXPool.QueryRow(ctx, "select server, secret_box_key, private_box_key, public_box_key, private_sign_key, public_sign_key from secrt.hostname join secrt.server using (server) where hostname=$1", hostname)

	server := SecretServer{
		Hostname: hostname,
	}
	err := row.Scan(&server.Server, &server.SecretBoxKey, &server.PrivateBoxKey, &server.PublicBoxKey, &server.PrivateSignKey, &server.PublicSignKey)
	if err != nil {
		return nil, fmt.Errorf("unable to find server %s: %w", hostname, err)
	}

	return &server, nil
}

func (server *SecretServer) GetPeer(alias string) (*Peer, bool) {
	ctx := context.Background()

	peer := Peer{
		Server: server.Server,
		Alias:  alias,
	}

	row := PGXPool.QueryRow(ctx, "select peer, public_box_key from secrt.peer where server=$1 and alias=$2", server.Server, alias)
	err := row.Scan(&peer.Peer, &peer.PublicKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false
		}
		log.Printf("error attempting to read peer %s: %v", alias, err)
		return nil, false
	}

	return &peer, true
}

func (server *SecretServer) Authenticate(r *http.Request) (*Peer, *jtp.HTTPError) {
	sig := r.Header.Get("Signature")
	if sig == "" {
		return nil, jtp.UnauthorizedError(fmt.Errorf("missing signature header"))
	}

	// Signature is base64-encoded JSON
	js, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, jtp.UnauthorizedError(fmt.Errorf("invalid signature encoding: %w", err))
	}

	var signature secrt.Signature
	if err = json.Unmarshal(js, &signature); err != nil {
		return nil, jtp.UnauthorizedError(fmt.Errorf("invalid signature: %w", err))
	}

	ciphertext := signature.Sig

	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, jtp.UnauthorizedError(fmt.Errorf("signature version %d is not supported", ciphertext[0]))
	}

	peer, ok := server.GetPeer(signature.Peer)
	if !ok {
		return nil, jtp.UnauthorizedError(fmt.Errorf("unknown peer %q", signature.Peer))
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	plaintext, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peer.PublicKey), secrt.To32(server.PrivateBoxKey))
	if !ok {
		return nil, jtp.UnauthorizedError(fmt.Errorf("failed authenticate message from %s", peer.Alias))
	}

	timestamp, err := strconv.ParseInt(string(plaintext), 10, 64)
	if err != nil {
		return nil, jtp.UnauthorizedError(fmt.Errorf("invalid timestamp: %w", err))
	}

	// check time window
	now := time.Now().Unix()
	diff := now - timestamp
	if diff > Config.SignatureSkew || diff < -Config.SignatureSkew {
		return nil, jtp.UnauthorizedError(errors.New("signature expired"))
	}

	return peer, nil
}

// dispatch is a simple wrapper for jtp.Handle that finds the appropriate server and calls the given function on it.
func dispatch[IN any, OUT any](method func(*SecretServer, *http.Request, *IN) (*OUT, error)) http.HandlerFunc {
	return jtp.Handle(func(w http.ResponseWriter, r *http.Request, in *IN) (*OUT, error) {
		host := GetHostname(r)
		s, err := GetSecretServer(host)
		if err != nil {
			return nil, jtp.NotFoundError(fmt.Errorf("unable to find secret server %s: %w", host, err))
		}

		return method(s, r, in)
	})
}

func GetHostname(r *http.Request) string {

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return scheme + "://" + r.Host
}

func StartServer() error {
	if err := initConfig(); err != nil {
		secrt.Exit(1, err)
	}

	mux := http.NewServeMux()

	pathPrefix := Config.PathPrefix

	// The server works by finding a SecretServer based on the request's hostname, and then dispatching
	// to a function on that server.
	//
	// The unusual syntax (*SecretServer).functionName is a function expression representing a method.
	// It returns a function whose first argument is the target object. The generic dispatch
	// function uses the arguments of the method to infer the types.
	//
	// This makes things really easy to code and eliminates a number of gotchas in the standard
	// library, but it takes a little getting used to.

	mux.HandleFunc("POST "+pathPrefix+"enrol/{peer}", dispatch((*SecretServer).handleEnrol))
	mux.HandleFunc("GET "+pathPrefix+"inbox", dispatch((*SecretServer).handleGetInbox))
	mux.HandleFunc("POST "+pathPrefix+"message/{recipient}", dispatch((*SecretServer).handlePostMessage))
	mux.HandleFunc("GET "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleGetMessage))
	mux.HandleFunc("DELETE "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleDeleteMessage))
	mux.HandleFunc("GET "+pathPrefix+"peer/{peer}", dispatch((*SecretServer).handleGetPeer))
	mux.HandleFunc("POST "+pathPrefix+"invite/{peer}", dispatch((*SecretServer).handleInvite))
	mux.HandleFunc("GET "+pathPrefix+"challenge", dispatch((*SecretServer).handleGetChallenge))

	// POST performs the enrolment. GET displays the HTML activation page.
	mux.HandleFunc("POST "+pathPrefix+"activate", dispatch((*SecretServer).handlePostActivate))
	mux.HandleFunc("GET "+pathPrefix+"activate", handleGetActivate)

	log.Println("listening on :8080")
	return http.ListenAndServe(":8080", mux)
}
