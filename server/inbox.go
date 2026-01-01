package server

import (
	"encoding/json"
	"net/http"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetInbox(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Don't show old messages
	peer.ejectMessages()

	// 204 just means there's nothing here. No messages!
	if len(peer.Messages) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	inbox := &secrt.Inbox{
		Messages: make([]secrt.InboxMessage, 0, len(peer.Messages)),
	}

	for _, msg := range peer.Messages {
		inbox.Messages = append(inbox.Messages, secrt.InboxMessage{
			ID:        msg.ID,
			Sender:    msg.Sender.PeerID,
			Timestamp: msg.Timestamp.Unix(),
			Size:      len(msg.Payload),
			Metadata:  msg.Metadata,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(inbox)
}
