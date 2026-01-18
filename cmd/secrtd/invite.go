package main

import (
	"log"
	"net/http"
)

func (server *SecretServer) handleInvite(w http.ResponseWriter, r *http.Request) {
	_, err := server.Authenticate(r)
	if err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, err)
		return
	}

	peerID := r.PathValue("peer")
	log.Println("received invite request for user:", peerID)
}
