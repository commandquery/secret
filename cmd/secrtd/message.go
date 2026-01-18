package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

func (server *SecretServer) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	sender, err := server.Authenticate(r)
	if err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, err)
		return
	}

	recipientID := r.PathValue("recipient")
	if recipientID == "" {
		_ = WriteStatus(w, http.StatusBadRequest, err)
		return
	}

	recipient, ok := server.GetPeer(recipientID)
	if !ok {
		_ = WriteStatus(w, http.StatusNotFound, err)
		return
	}

	// Messages are sent in an Envelope that contains separately encrypted
	// Metadata and Payload objects.
	r.Body = http.MaxBytesReader(w, r.Body, secrt.MessageSizeLimit)
	envelopeJS, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("unable to read body:", err)
		_ = WriteStatus(w, http.StatusBadRequest, err)
		return
	}

	var envelope secrt.Envelope
	if err = json.Unmarshal(envelopeJS, &envelope); err != nil {
		log.Println("unable to parse envelope:", err)
		_ = WriteStatus(w, http.StatusBadRequest, err)
		return
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

	ctx := context.Background()
	_, err = PGXPool.Exec(ctx, "insert into secrt.message (server, peer, message, sender, received, metadata, payload) values ($1, $2, $3, $4, $5, $6, $7)",
		newMessage.Server, newMessage.Peer, newMessage.Message, newMessage.Sender, newMessage.Received, envelope.Metadata, envelope.Payload)
	if err != nil {
		log.Println("unable to insert message:", err)
		_ = WriteStatus(w, http.StatusInternalServerError, err)
		return
	}

	//recipient.AddMessage(newMessage)
	log.Println("sent message", newMessage.Message)

	// Tell the sender the message ID
	resp := secrt.SendResponse{
		ID: newMessage.Message,
	}

	_ = json.NewEncoder(w).Encode(resp)

}

func (server *SecretServer) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, err)
		return
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		_ = WriteStatus(w, http.StatusBadRequest, err)
		return
	}

	message, err := GetMessage(peer, id)
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Add("Peer-ID", message.SenderAlias)
	w.Header().Add("Content-Type", "application/octet-stream")
	_, _ = w.Write(message.Payload)
}

func (server *SecretServer) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, err)
		return
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		_ = WriteStatus(w, http.StatusBadRequest, err)
		return
	}

	msg, err := GetMessage(peer, id)
	if err != nil {
		WriteError(w, err)
		return
	}

	if err = msg.Delete(); err != nil {
		WriteError(w, err)
		return
	}

	w.WriteHeader(http.StatusOK)
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
		return nil, fmt.Errorf("message id %s not found", messageId)
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
