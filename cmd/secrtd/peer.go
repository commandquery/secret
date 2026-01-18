package main

import (
	"encoding/binary"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/commandquery/secrt"
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

func (server *SecretServer) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	if _, err := server.Authenticate(r); err != nil {
		_ = WriteStatus(w, http.StatusUnauthorized, nil)
		return
	}

	peerID := r.PathValue("peer")
	if peerID == "" {
		_ = WriteStatus(w, http.StatusBadRequest, nil)
		return
	}

	user, ok := server.GetPeer(peerID)
	if !ok {
		_ = WriteStatus(w, http.StatusNotFound, nil)
		return
	}

	peer := secrt.Peer{
		Peer:      peerID,
		PublicKey: user.PublicKey,
	}

	peerjs, err := json.Marshal(peer)
	if err != nil {
		log.Println("unable to marshal peer:", err)
		_ = WriteStatus(w, http.StatusInternalServerError, err)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(peerjs)
}
