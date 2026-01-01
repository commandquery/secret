package server

import (
	"log"
	"net/http"
)

func (server *SecretServer) handleInvite(w http.ResponseWriter, r *http.Request) {
	_, err := server.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	peerID := r.PathValue("peer")
	log.Println("received invite request for user:", peerID)
}
