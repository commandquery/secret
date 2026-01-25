package main

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
)

func (server *SecretServer) handleActivate(r *http.Request, req *secrt.ActivationRequest) (*secrt.ActivationResponse, error) {
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
