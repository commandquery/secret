package secrt

import (
	"github.com/google/uuid"
)

// MessageSizeLimit limits the size of individual messages.
const MessageSizeLimit = 50 * 1024 // 100 KiB

// Inbox is the JSON struct used to represent the inbox.
type Inbox struct {
	Messages []Message `json:"messages"`
}

type Message struct {
	Message   uuid.UUID `json:"id"`
	Sender    string    `json:"sender"`
	Timestamp int64     `json:"timestamp"`
	Size      int       `json:"size"`     // encrypted size. used as a hint.
	Metadata  []byte    `json:"metadata"` // encrypted metadata, contains unencrypted size.
	Payload   []byte    `json:"payload"`  // note that this is empty for inbox lookups
}

type Metadata struct {
	Description string `json:"description"`
	Size        int    `json:"size"`
	Filename    string `json:"filename"`
}

// SendRequest wraps encrypted metadata with the encrypted payload.
// Metadata is returned for 'secrt ls', while the payload is returned
// for 'secrt get'.
type SendRequest struct {
	Payload  []byte `json:"payload"`
	Metadata []byte `json:"metadata"` // encrypted secret.Metadata (json)
}

type Signature struct {
	Peer string `json:"peer"`
	Sig  []byte `json:"sig"`
}

// SendResponse is the message ID returned by the server after a share.
type SendResponse struct {
	ID uuid.UUID `json:"id"`
}

type Peer struct {
	Peer      string `json:"peer"`
	PublicKey []byte `json:"publicKey"`
}

type Challenge struct {
	Version    int    `json:"version"`
	Complexity int    `json:"complexity"`
	Timestamp  int64  `json:"timestamp"`
	Challenge  []byte `json:"challenge"`
}

// ChallengeRequest wraps a challenge object with a signature.
// The entire signedChallenge must be returned along with the
// result. The signature, timestamp and proof are then checked.
// This enables stateless hashcash challenges, with nothing stored on the
// server side.
type ChallengeRequest struct {
	Challenge []byte `json:"challenge"`
}

// ChallengeResponse is returned by the client. It contains both the
// original, signed challenge, and the nonce.
type ChallengeResponse struct {
	Challenge []byte `json:"challenge"`
	Nonce     uint64 `json:"nonce"`
}

type EnrolmentRequest struct {
	PublicKey []byte `json:"publicKey"`
}

const (
	EnrolStatusComplete = "complete" // The enrolment succeeded
	EnrolStatusActivate = "activate" // Enrolment requires activation.
)

type EnrolmentResponse struct {
	ServerKey []byte `json:"serverKey"`
	Activated bool   `json:"activated"`
}

type ActivationRequest struct {
	Token string `json:"token"`
	Code  int    `json:"code"`
}

type ValidationResponse struct {
}
