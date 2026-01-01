package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/commandquery/secrt"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
)

// MessageInboxLimit limits the number of messages per user
// If exceeded, the oldest message is silently deleted.
const MessageInboxLimit = 10

// MessageExpiry limits how long a message is stored.
const MessageExpiry time.Duration = 24 * time.Hour

var ErrExistingPeer error = errors.New("peer already exists")
var ErrAmbiguousMessageID error = errors.New("ambiguous message ID")
var ErrUnknownMessageID error = errors.New("unknown message ID")

type SecretServer struct {
	lock           sync.Mutex
	Path           string           `json:"-"` // where this config was loaded
	PrivateBoxKey  []byte           `json:"privateBoxKey"`
	PublicBoxKey   []byte           `json:"publicBoxKey"`
	PrivateSignKey []byte           `json:"privateSignKey"`
	PublicSignKey  []byte           `json:"publicSignKey"`
	Peers          map[string]*Peer `json:"peers"`
	SignatureSkew  int64            `json:"signatureskew"` // allowable time skew for authentication nonce, seconds.
	ChallengeSize  int              `json:"challengeSize"` // Number of hashcash bits to use
	AutoEnrol      string           `json:"-"`             // Allow auto-enrolment? (taken from environment)
}

type Message struct {
	ID        uuid.UUID
	Sender    *Peer
	Timestamp time.Time
	Metadata  []byte
	Payload   []byte
}

// NewSecretServer returns a new SecretServer with a unique private and public key.
func NewSecretServer(path string, autoEnrol string) *SecretServer {
	publicBoxKey, privateBoxKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	publicSignKey, privateSignKey, err := sign.GenerateKey(rand.Reader)

	server := &SecretServer{
		Path:           path,
		PrivateBoxKey:  privateBoxKey[:],
		PublicBoxKey:   publicBoxKey[:],
		PrivateSignKey: privateSignKey[:],
		PublicSignKey:  publicSignKey[:],
		AutoEnrol:      autoEnrol,
		SignatureSkew:  Config.SignatureSkew,
		ChallengeSize:  Config.ChallengeSize,
		Peers:          make(map[string]*Peer),
	}

	return server
}

func LoadServerState(path string) (*SecretServer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	secretServer := &SecretServer{
		Path: path,
	}

	err = json.NewDecoder(f).Decode(secretServer)
	if err != nil {
		return nil, err
	}

	return secretServer, nil
}

func (server *SecretServer) Save() error {
	// FIXME: write-and-replace rather than overwrite.
	f, err := os.OpenFile(server.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(server)
}

func (server *SecretServer) GetUser(uid string) (user *Peer, ok bool) {
	user, ok = server.Peers[uid]
	return
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

	peer, ok := server.Peers[signature.Peer]
	if !ok {
		return nil, fmt.Errorf("unknown peer %q", signature.Peer)
	}

	var nonce [24]byte
	copy(nonce[:], ciphertext[1:25])

	var out []byte
	plaintext, ok := box.Open(out, ciphertext[25:], &nonce, secrt.To32(peer.PublicKey), secrt.To32(server.PrivateBoxKey))
	if !ok {
		return nil, fmt.Errorf("unable to authenticate message from %s", peer.PeerID)
	}

	timestamp, err := strconv.ParseInt(string(plaintext), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	// check time window
	now := time.Now().Unix()
	diff := now - timestamp
	if diff > server.SignatureSkew || diff < -server.SignatureSkew {
		return nil, errors.New("signature expired")
	}

	return peer, nil
}

func WriteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnknownMessageID):
		http.Error(w, "unknown message id", http.StatusNotFound)
		return
	case errors.Is(err, ErrAmbiguousMessageID):
		http.Error(w, "ambiguous message id", http.StatusConflict)
		return
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func StartServer() error {
	if err := initConfig(); err != nil {
		secrt.Exit(1, err)
	}

	mux := http.NewServeMux()

	server, err := LoadServerState(Config.ServerConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		server = NewSecretServer(Config.ServerConfigPath, Config.AutoEnrol)
		if err = server.Save(); err != nil {
			return fmt.Errorf("failed to init server: %w", err)
		}
	} else {
		if err != nil {
			return err
		}
	}

	pathPrefix := Config.PathPrefix

	mux.HandleFunc("POST "+pathPrefix+"enrol/{peer}", server.handleEnrol)

	mux.HandleFunc("GET "+pathPrefix+"inbox", server.handleGetInbox)

	mux.HandleFunc("POST "+pathPrefix+"message/{recipient}", server.handlePostMessage)
	mux.HandleFunc("GET "+pathPrefix+"message/{id}", server.handleGetMessage)
	mux.HandleFunc("DELETE "+pathPrefix+"message/{id}", server.handleDeleteMessage)

	mux.HandleFunc("GET "+pathPrefix+"peer/{peer}", server.handleGetPeer)

	mux.HandleFunc("POST "+pathPrefix+"invite/{peer}", server.handleInvite)

	mux.HandleFunc("GET "+pathPrefix+"challenge", server.handleGetChallenge)

	log.Println("listening on :8080")
	return http.ListenAndServe(":8080", mux)
}
