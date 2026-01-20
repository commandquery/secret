package main

import (
	"context"
	"fmt"
	"time"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetInbox(ctx context.Context, _ *EMPTY) (*secrt.Inbox, *HTTPError) {
	peer, aerr := server.Authenticate(GetRequest(ctx))
	if aerr != nil {
		return nil, aerr
	}

	rows, err := PGXPool.Query(ctx,
		`select message, peer.alias, received, metadata
				from secrt.message join secrt.peer on (peer.server = message.server and peer.peer = message.sender)
				where message.server=$1 and message.peer=$2 order by received`, server.Server, peer.Peer)
	if err != nil {
		return nil, ErrInternalServerError(fmt.Errorf("unable to query inbox: %w", err))
	}

	defer rows.Close()

	inbox := &secrt.Inbox{
		Messages: []secrt.Message{},
	}

	for rows.Next() {
		var timestamp time.Time
		msg := secrt.Message{}
		if err := rows.Scan(&msg.Message, &msg.Sender, &timestamp, &msg.Metadata); err != nil {
			return nil, ErrInternalServerError(fmt.Errorf("unable to read inbox: %w", err))
		}

		msg.Timestamp = timestamp.Unix()

		inbox.Messages = append(inbox.Messages, msg)
	}

	// 204 just means there's nothing here. No messages!
	if len(inbox.Messages) == 0 {
		return nil, ErrNoContent()
	}

	return inbox, nil
}
