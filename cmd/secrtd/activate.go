package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

//go:embed ui/activate.html
var activatePage string

func (server *SecretServer) handlePostActivate(r *http.Request, req *secrt.ActivationRequest) (*secrt.ActivationResponse, error) {
	token, err := base64.RawURLEncoding.DecodeString(req.Token)
	if err != nil {
		return nil, jtp.BadRequestError(fmt.Errorf("invalid token: %w", err))
	}

	_, err = PGXPool.Exec(r.Context(), "select secrt.activate($1, $2)", token, req.Code)
	if err != nil {
		return nil, jtp.BadRequestError(err)
	}

	return &secrt.ActivationResponse{
		Message: "Welcome to secrt!",
	}, nil
}

func handleGetActivate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Write([]byte(activatePage))
}
