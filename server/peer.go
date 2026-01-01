package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/commandquery/secrt"
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

func (server *SecretServer) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	if _, err := server.Authenticate(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	peerID := r.PathValue("peer")
	if peerID == "" {
		http.Error(w, "missing peer", http.StatusBadRequest)
		return
	}

	user, ok := server.GetUser(peerID)
	if !ok {
		http.Error(w, "unknown peer", http.StatusNotFound)
		return
	}

	peer := secrt.Peer{
		Peer:      peerID,
		PublicKey: user.PublicKey,
	}

	peerjs, err := json.Marshal(peer)
	if err != nil {
		log.Println("unable to marshal peer:", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(peerjs)
}
