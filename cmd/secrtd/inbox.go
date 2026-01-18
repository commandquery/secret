package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetInbox(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, err)
		return
	}

	ctx := context.Background()
	rows, err := PGXPool.Query(ctx,
		`select message, peer.alias, received, metadata
				from secrt.message join secrt.peer on (peer.server = message.server and peer.peer = message.sender)
				where message.server=$1 and message.peer=$2 order by received`, server.Server, peer.Peer)
	if err != nil {
		log.Printf("error fetching messages: %v", err)
		_ = WriteStatus(w, http.StatusInternalServerError, err)
		return
	}

	defer rows.Close()

	inbox := &secrt.Inbox{
		Messages: []secrt.InboxMessage{},
	}

	for rows.Next() {
		var timestamp time.Time
		msg := secrt.InboxMessage{}
		if err := rows.Scan(&msg.Message, &msg.Sender, &timestamp, &msg.Metadata); err != nil {
			log.Printf("unable to read inbox: %v", err)
			_ = WriteStatus(w, http.StatusInternalServerError, err)
			return
		}

		msg.Timestamp = timestamp.Unix()

		inbox.Messages = append(inbox.Messages, msg)
	}

	// 204 just means there's nothing here. No messages!
	if len(inbox.Messages) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(inbox)
}
