package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/commandquery/secrt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Message is the internal representation of a message. Use secrt.Message to
// transfer a message to a client.
type Message struct {
	Server      uuid.UUID
	Peer        uuid.UUID
	Message     uuid.UUID
	Sender      uuid.UUID
	SenderAlias string
	Received    time.Time
	Metadata    []byte
	Payload     []byte
}

func (server *SecretServer) handlePostMessage(ctx context.Context, envelope *secrt.SendRequest) (*secrt.SendResponse, *secrt.HTTPError) {
	r := GetRequest(ctx)
	sender, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	recipientID := r.PathValue("recipient")
	if recipientID == "" {
		return nil, secrt.BadRequestError(fmt.Errorf("missing recipient"))
	}

	recipient, ok := server.GetPeer(recipientID)
	if !ok {
		return nil, secrt.NotFoundError(fmt.Errorf("recipient not found"))
	}

	newMessage := &Message{
		Server:      server.Server,
		Peer:        recipient.Peer,
		Message:     uuid.New(),
		Sender:      sender.Peer,
		SenderAlias: sender.Alias,
		Received:    time.Now(),
		Metadata:    envelope.Metadata,
		Payload:     envelope.Payload,
	}

	_, err := PGXPool.Exec(ctx, "insert into secrt.message (server, peer, message, sender, received, metadata, payload) values ($1, $2, $3, $4, $5, $6, $7)",
		newMessage.Server, newMessage.Peer, newMessage.Message, newMessage.Sender, newMessage.Received, envelope.Metadata, envelope.Payload)
	if err != nil {
		return nil, secrt.InternalServerError(fmt.Errorf("unable to insert message: %w", err))
	}

	//recipient.AddMessage(newMessage)
	log.Println("sent message", newMessage.Message)

	// Tell the sender the message ID
	return &secrt.SendResponse{
		ID: newMessage.Message,
	}, nil
}

func (server *SecretServer) handleGetMessage(ctx context.Context, _ *EMPTY) (*secrt.Message, *secrt.HTTPError) {

	//func (server *SecretServer) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	r := GetRequest(ctx)
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		return nil, secrt.BadRequestError(fmt.Errorf("invalid message id"))
	}

	msg, err := GetMessage(peer, id)
	if err != nil {
		if errors.Is(err, ErrUnknownMessageID) {
			return nil, secrt.NotFoundError(err)
		}
		if errors.Is(err, ErrAmbiguousMessageID) {
			return nil, secrt.BadRequestError(err)
		}
		return nil, secrt.InternalServerError(fmt.Errorf("error while retrieving message: %w", err))
	}

	return &secrt.Message{
		Message:   msg.Message,
		Sender:    msg.SenderAlias,
		Timestamp: msg.Received.Unix(),
		Metadata:  msg.Metadata,
		Payload:   msg.Payload,
	}, nil
}

func (server *SecretServer) handleDeleteMessage(ctx context.Context, _ *EMPTY) (*EMPTY, *secrt.HTTPError) {
	//func (server *SecretServer) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	r := GetRequest(ctx)
	peer, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		return nil, secrt.BadRequestError(fmt.Errorf("invalid message id"))
	}

	msg, err := GetMessage(peer, id)
	if err != nil {
		if errors.Is(err, ErrUnknownMessageID) {
			return nil, secrt.NotFoundError(err)
		}
		if errors.Is(err, ErrAmbiguousMessageID) {
			return nil, secrt.BadRequestError(err)
		}
	}

	if err = msg.Delete(); err != nil {
		return nil, secrt.InternalServerError(fmt.Errorf("unable to delete message: %w", err))
	}

	return nil, nil
}

func (msg *Message) Delete() error {
	_, err := PGXPool.Exec(context.Background(), "delete from secrt.message where server=$1 and message=$2", msg.Server, msg.Message)
	if err != nil {
		return fmt.Errorf("unable to delete message: %w", err)
	}

	return nil
}

// GetMessage finds a message by either it's full ID or its prefix.
// Returns an error if multiple messages match the prefix.
// Short message IDs are a convenience for CLI users, but scripts should always
// use the long ID to avoid potential duplicate message errors.
func GetMessage(peer *Peer, messageId string) (*Message, error) {

	ctx := context.Background()
	msgQuery := "select message, sender, peer.alias, received, metadata, payload from secrt.message join secrt.peer on (peer.server = message.server and peer.peer = message.sender) "

	var rows pgx.Rows
	var sqlErr error

	// Perform a different query based on the length of the message ID.
	// If it's an 8-hex-digit prefix, do a range search. Otherwise, do an exact search.
	if len(messageId) == 8 {
		prefix, err := prefixFromHex(messageId)
		if err != nil {
			return nil, fmt.Errorf("invalid message id %s: %w", messageId, err)
		}
		lower, upper := uuidBoundsFromPrefix(prefix)
		rows, sqlErr = PGXPool.Query(ctx, msgQuery+"where message.server=$1 and message.peer=$2 and message between $3 and $4", peer.Server, peer.Peer, lower, upper)
	} else if len(messageId) == 36 {
		exactId, err := uuid.Parse(messageId)
		if err != nil {
			return nil, ErrUnknownMessageID
		}
		rows, sqlErr = PGXPool.Query(ctx, msgQuery+"where message.server=$1 and message.peer=$2 and message=$3", peer.Server, peer.Peer, exactId)
	} else {
		return nil, fmt.Errorf("invalid message id %s", messageId)
	}

	if sqlErr != nil {
		return nil, fmt.Errorf("unable to fetch messages: %w", sqlErr)
	}

	defer rows.Close()

	if !rows.Next() {
		return nil, ErrUnknownMessageID
	}

	msg := Message{
		Server: peer.Server,
		Peer:   peer.Peer,
	}

	if err := rows.Scan(&msg.Message, &msg.Sender, &msg.SenderAlias, &msg.Received, &msg.Metadata, &msg.Payload); err != nil {
		return nil, fmt.Errorf("unable to read message: %w", err)
	}

	// If the query returns multiple rows, we have two msg IDs with the same prefix.
	// Rather than return the wrong secret, we error out.
	if rows.Next() {
		return nil, ErrAmbiguousMessageID
	}

	return &msg, nil
}
