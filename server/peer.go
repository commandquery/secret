package server

import (
	"strings"
	"sync"
	"time"
)

// Peer is a peer who's enrolled in this server instance.
type Peer struct {
	lock      sync.Mutex
	PeerID    string     `json:"peerID"`
	PublicKey []byte     `json:"publicKey"`
	Messages  []*Message `json:"-"` // messages are transient, at least for now.
}

// ejectMessages ejects old messages.
// WARNING: Peer MUST be locked before calling ejectMessages.
func (user *Peer) ejectMessages() {
	cutoff := time.Now().Add(-MessageExpiry)
	for index, message := range user.Messages {
		if message.Timestamp.After(cutoff) {
			// messages are stored in order.
			if index > 0 {
				user.Messages = user.Messages[index:]
			}
			return
		}
	}

	// All messages expired (or slice was empty)
	user.Messages = nil
}

// Select a message by its prefix. Returns an error if multiple messages match.
func (peer *Peer) getMessage(messageId string) (*Message, error) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	messageId = strings.ToLower(messageId)
	var selected *Message

	for _, msg := range peer.Messages {
		if strings.HasPrefix(msg.ID.String(), messageId) {
			if selected != nil {
				return nil, ErrAmbiguousMessageID
			}

			selected = msg
		}
	}

	if selected == nil {
		return nil, ErrUnknownMessageID
	}

	return selected, nil
}

func (peer *Peer) DeleteMessage(deleted *Message) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	for i, msg := range peer.Messages {
		if deleted.ID == msg.ID {
			peer.Messages = append(peer.Messages[:i], peer.Messages[i+1:]...)
			return
		}
	}

	return
}

func (peer *Peer) AddMessage(msg *Message) {
	peer.lock.Lock()
	defer peer.lock.Unlock()

	peer.ejectMessages()

	if len(peer.Messages) == MessageInboxLimit {
		peer.Messages = peer.Messages[1:]
	}

	peer.Messages = append(peer.Messages, msg)
}
