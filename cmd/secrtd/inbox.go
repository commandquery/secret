package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handleGetInbox(r *http.Request, _ *jtp.None) (*secrt.Inbox, error) {
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	rows, err := PGXPool.Query(r.Context(),
		`select message, received, metadata, claims from secrt.message
				where message.server=$1 and message.peer=$2 order by received`, server.Server, peer.Peer)
	if err != nil {
		return nil, jtp.InternalServerError(fmt.Errorf("unable to query inbox: %w", err))
	}

	defer rows.Close()

	inbox := &secrt.Inbox{
		Messages: []secrt.Message{},
	}

	for rows.Next() {
		var timestamp time.Time
		msg := secrt.Message{}
		if err := rows.Scan(&msg.Message, &timestamp, &msg.Metadata, &msg.Claims); err != nil {
			return nil, jtp.InternalServerError(fmt.Errorf("unable to read inbox: %w", err))
		}

		msg.Timestamp = timestamp.Unix()

		inbox.Messages = append(inbox.Messages, msg)
	}

	// 204 just means there's nothing here. No messages!
	if len(inbox.Messages) == 0 {
		return nil, jtp.NoContentError()
	}

	return inbox, nil
}
