package server

import (
	"encoding/json"
	"net/http"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetChallenge(w http.ResponseWriter, r *http.Request) {
	challengeRequest, err := secrt.NewChallenge(server.ChallengeSize, server.PrivateSignKey)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(challengeRequest)
}
