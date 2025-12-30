package secrt

import "github.com/google/uuid"

// Inbox is the JSON struct used to represent the inbox.
type Inbox struct {
	Messages []InboxMessage `json:"messages"`
}

type InboxMessage struct {
	ID        uuid.UUID `json:"id"`
	Sender    string    `json:"sender"`
	Timestamp int64     `json:"timestamp"`
	Size      int       `json:"size"`     // encrypted size. used as a hint.
	Metadata  []byte    `json:"metadata"` // encrypted metadata, contains unencrypted size.
}

type Metadata struct {
	Description string `json:"description"`
	Size        int    `json:"size"`
	Filename    string `json:"filename"`
}

// Envelope wraps encrypted metadata with the encrypted payload.
// Metadata is returned for 'secrt ls', while the payload is returned
// for 'secrt get'.
type Envelope struct {
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
