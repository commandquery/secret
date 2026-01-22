package main

import (
	"context"
	"log"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleInvite(ctx context.Context, _ *EMPTY) (*EMPTY, *secrt.HTTPError) {
	r := GetRequest(ctx)
	_, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	peerID := r.PathValue("peer")
	log.Println("received invite request for user:", peerID)
	return nil, nil
}
