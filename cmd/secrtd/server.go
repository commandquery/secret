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
	"strings"
	"time"

	"github.com/commandquery/secrt"
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
	PrivateBoxKey  []byte `json:"privateBoxKey"`
	PublicBoxKey   []byte `json:"publicBoxKey"`
	PrivateSignKey []byte `json:"privateSignKey"`
	PublicSignKey  []byte `json:"publicSignKey"`
}

// NewSecretServer returns a new SecretServer with a unique private and public key.
func NewSecretServer() *SecretServer {
	publicBoxKey, privateBoxKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	publicSignKey, privateSignKey, err := sign.GenerateKey(rand.Reader)

	server := &SecretServer{
		Server:         uuid.New(),
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
	row := PGXPool.QueryRow(ctx, "select server, private_box_key, public_box_key, private_sign_key, public_sign_key from secrt.hostname join secrt.server using (server) where hostname=$1", hostname)

	server := SecretServer{}
	err := row.Scan(&server.Server, &server.PrivateBoxKey, &server.PublicBoxKey, &server.PrivateSignKey, &server.PublicSignKey)
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

func (server *SecretServer) Authenticate(r *http.Request) (*Peer, error) {
	sig := r.Header.Get("Signature")
	if sig == "" {
		return nil, errors.New("missing signature header")
	}

	// Signature is base64-encoded JSON
	js, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	var signature secrt.Signature
	if err = json.Unmarshal(js, &signature); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	ciphertext := signature.Sig

	// Check that the version number works with us.
	if ciphertext[0] != 0 {
		return nil, fmt.Errorf("ciphertext version (%d) is not supported. Try upgrading `secret`.", ciphertext[0])
	}

	peer, ok := server.GetPeer(signature.Peer)
	if !ok {
		return nil, fmt.Errorf("unknown peer %q", signature.Peer)
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	plaintext, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peer.PublicKey), secrt.To32(server.PrivateBoxKey))
	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peer.Alias)
	}

	timestamp, err := strconv.ParseInt(string(plaintext), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	// check time window
	now := time.Now().Unix()
	diff := now - timestamp
	if diff > Config.SignatureSkew || diff < -Config.SignatureSkew {
		return nil, errors.New("signature expired")
	}

	return peer, nil
}

func WriteError(w http.ResponseWriter, err error) {
	log.Println(err)
	switch {
	case errors.Is(err, ErrUnknownMessageID):
		http.Error(w, "unknown message id", http.StatusNotFound)
		return
	case errors.Is(err, ErrAmbiguousMessageID):
		http.Error(w, "ambiguous message id", http.StatusConflict)
		return
	default:
		_ = WriteStatus(w, http.StatusInternalServerError, err)
		return
	}
}

// WriteStatus sets the HTTP status and sends a message. Returns the provided
// error, making it possible to call WriteStatus and return with an error in a single
// statement.
func WriteStatus(w http.ResponseWriter, status int, err error) error {
	http.Error(w, http.StatusText(status), status)
	return err
}

// Dispatch finds the server using the request hostname, and calls the given method on it.
// If the server can't be found, returns a 404.
// This mechanism ensures that all HTTP requests are gated through a specific server UUID.
func dispatch(method func(*SecretServer, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")

		s, err := GetSecretServer(host)
		if err != nil {
			log.Println(WriteStatus(w, http.StatusNotFound, err))
			return
		}
		method(s, w, r)
	}
}

func StartServer() error {
	if err := initConfig(); err != nil {
		secrt.Exit(1, err)
	}

	mux := http.NewServeMux()

	pathPrefix := Config.PathPrefix

	// The server works by finding a SecretServer based on the request's hostname, and then dispatching
	// to a function on that server.

	mux.HandleFunc("POST "+pathPrefix+"enrol/{peer}", dispatch((*SecretServer).handleEnrol))
	mux.HandleFunc("GET "+pathPrefix+"inbox", dispatch((*SecretServer).handleGetInbox))
	mux.HandleFunc("POST "+pathPrefix+"message/{recipient}", dispatch((*SecretServer).handlePostMessage))
	mux.HandleFunc("GET "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleGetMessage))
	mux.HandleFunc("DELETE "+pathPrefix+"message/{id}", dispatch((*SecretServer).handleDeleteMessage))
	mux.HandleFunc("GET "+pathPrefix+"peer/{peer}", dispatch((*SecretServer).handleGetPeer))
	mux.HandleFunc("POST "+pathPrefix+"invite/{peer}", dispatch((*SecretServer).handleInvite))
	mux.HandleFunc("GET "+pathPrefix+"challenge", dispatch((*SecretServer).handleGetChallenge))

	log.Println("listening on :8080")
	return http.ListenAndServe(":8080", mux)
}
