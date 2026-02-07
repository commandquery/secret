package main

import (
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
	"github.com/commandquery/secrt/jtp"
	"github.com/google/uuid"
)

// Peer is a peer who's enrolled in this server instance.
type Peer struct {
	Server    uuid.UUID
	Peer      uuid.UUID
	Alias     string
	PublicKey []byte
}

func prefixFromHex(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err
}

func uuidBoundsFromPrefix(prefix uint32) (lower, upper uuid.UUID) {
	binary.BigEndian.PutUint32(lower[:4], prefix)
	binary.BigEndian.PutUint32(upper[:4], prefix+1)
	return lower, upper
}

func (server *SecretServer) handleGetPeer(r *http.Request, _ *jtp.None) (*secrt.Peer, error) {

	if _, err := server.Authenticate(r); err != nil {
		return nil, err
	}

	alias := r.PathValue("alias")
	if alias == "" {
		return nil, jtp.BadRequestError(fmt.Errorf("missing peer parameter"))
	}

	peer, ok := server.GetPeer(alias)
	if !ok {
		return nil, jtp.NotFoundError(fmt.Errorf("peer not found"))
	}

	return &secrt.Peer{
		Peer:      alias,
		PublicKey: peer.PublicKey,
	}, nil
}
