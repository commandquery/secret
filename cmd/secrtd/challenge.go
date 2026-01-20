package main

import (
	"context"

	"github.com/commandquery/secrt"
)

func (server *SecretServer) handleGetChallenge(ctx context.Context, _ *EMPTY) (*secrt.ChallengeRequest, *HTTPError) {
	challengeRequest, err := secrt.NewChallenge(Config.ChallengeSize, server.PrivateSignKey)
	if err != nil {
		return nil, ErrInternalServerError(err)
	}

	return challengeRequest, nil
}
