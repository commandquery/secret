package main

import (
	"encoding/json"
	"net/http"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	challengeRequest, err := secrt.NewChallenge(Config.ChallengeSize, server.PrivateSignKey)
	if err != nil {
		_ = WriteStatus(w, http.StatusInternalServerError, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(challengeRequest)
}
