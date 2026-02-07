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

	alias := r.PathValue("alias")
	log.Println("received invite request for user:", alias)
	return nil, nil
}
