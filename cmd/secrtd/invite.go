package main

import (
	"context"
	"log"
)

func (server *SecretServer) handleInvite(ctx context.Context, _ *EMPTY) (*EMPTY, *HTTPError) {
	r := GetRequest(ctx)
	_, aerr := server.Authenticate(r)
	if aerr != nil {
		return nil, aerr
	}

	peerID := r.PathValue("peer")
	log.Println("received invite request for user:", peerID)
	return nil, nil
}
