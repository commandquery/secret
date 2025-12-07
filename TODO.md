# not-so-secret TODO

- [ ] refactoring needed in secret.go (eg, Client struct is the config, secret.go is actually about config)
- [ ] client.go should probably be endpoint.go?
- [ ] ask before adding new peers
- [ ] support for multiple servers (eg, -s server)
- [ ] split client and server into their own packages
- [ ] server-side struct mutations aren't generally protected by a mutex.
- [ ] saving client or server config should be atomic
  - [ ] write to a temp file then move it.
- [ ] protect the private key on the client (eg with a passphrase)

## Done

- [X] allow the token for "secret add" to be a parameter rather than stdin
- [X] signature verification - can't sign messages using encryption key:
    - [X] add server public key to config
    - [X] encrypt a message for the server
    - [X] Signature: mark.lillywhite@emersion.com:xxxxxx
    - [X] "xxxx" is just the current timestamp, as a string
    - [X] encrypted for the server's public key, only the server can decrypt it
- [X] getPeer should download the peer key from the server if we don't have it.
    - [X] validate signature when getting public key for a peer (currently failing)
- [X] rename "UserID" to "PeerID"
