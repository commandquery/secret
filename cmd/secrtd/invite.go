package main

import (
	"log"
	"net/http"

	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handleInvite(r *http.Request, _ *jtp.None) (*jtp.None, error) {
	_, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	peerID := r.PathValue("peer")
	log.Println("received invite request for user:", peerID)
	return nil, nil
}
