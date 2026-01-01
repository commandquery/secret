package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/commandquery/secrt"
	"github.com/google/uuid"
)

func (server *SecretServer) handlePostMessage(w http.ResponseWriter, r *http.Request) {
	sender, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	recipientID := r.PathValue("recipient")
	if recipientID == "" {
		http.Error(w, "missing recipient", http.StatusBadRequest)
		return
	}

	recipient, ok := server.GetUser(recipientID)
	if !ok {
		http.Error(w, "unknown user", http.StatusNotFound)
		return
	}

	// Messages are sent in an Envelope that contains separately encrypted
	// Metadata and Payload objects.
	r.Body = http.MaxBytesReader(w, r.Body, secrt.MessageSizeLimit)
	envelopeJS, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("unable to read body:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var envelope secrt.Envelope
	if err = json.Unmarshal(envelopeJS, &envelope); err != nil {
		log.Println("unable to parse envelope:", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	newMessage := &Message{
		ID:        uuid.New(),
		Sender:    sender,
		Timestamp: time.Now(),
		Metadata:  envelope.Metadata,
		Payload:   envelope.Payload,
	}

	recipient.AddMessage(newMessage)
	log.Println("sent message", newMessage.ID)
	// Tell the sender the message ID
	resp := secrt.SendResponse{
		ID: newMessage.ID,
	}

	_ = json.NewEncoder(w).Encode(resp)

}

func (server *SecretServer) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		http.Error(w, fmt.Sprintf("invalid message id %s", id), http.StatusBadRequest)
		return
	}

	selected, err := peer.getMessage(id)
	if err != nil {
		WriteError(w, err)
		return
	}

	w.Header().Add("Peer-ID", selected.Sender.PeerID)
	w.Header().Add("Content-Type", "application/octet-stream")
	_, _ = w.Write(selected.Payload)
}

func (server *SecretServer) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	peer, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	id := r.PathValue("id")
	if len(id) != 8 && len(id) != 36 {
		http.Error(w, fmt.Sprintf("invalid message id %s", id), http.StatusBadRequest)
		return
	}

	selected, err := peer.getMessage(id)
	if err != nil {
		WriteError(w, err)
		return
	}

	peer.DeleteMessage(selected)

	w.WriteHeader(http.StatusOK)
}
