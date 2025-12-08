# not-so-secret TODO

- [X] need to be able to deploy with a static config for now (secret.emersion.com)
  - [X] add SECRET_AUTO_ENROL=approve option
  - [X] when set, this should log the peerID and key to the logs so I can add it manually 
- [X] static config file
  - [X] configure in deployment descriptor
  - [X] SECRET_CONFIG=/path/to/config
  - [X] make it write-protected (if it isn't)
- [ ] when a file is sent, also send the filename
  - [ ] filename in clear text so ls works, or can we decrypt it in ls?
  - [ ] if a filename is present, secret get should use it. never overwrite an existing file tho / --force
- [ ] split client and server into their own packages, only put main.go in cmd/secret
- [ ] protect the private key on the client (eg with a passphrase)
- [ ] refactoring needed in secret.go (eg, Client struct is the config, secret.go is actually about config)
- [ ] client.go should probably be endpoint.go?
- [ ] KISS: server should store messages and config in a PVC (or sqlite).
- [ ] ask before adding new peers
- [ ] when sending, search all servers for a peer rather than using the default peer
  - [ ] if the same peer is on two servers, select the first, print a warning & ask to continue
- [ ] support for multiple servers (eg, -s server)
- [ ] server-side struct mutations aren't generally protected by a mutex.
- [ ] saving client or server config should be atomic
  - [ ] write to a temp file then move it.

## Commercial & Public Stuff

- [ ] back with sqlite (?) - see https://pkg.go.dev/modernc.org/sqlite
- [ ] invite mechanism. - invite specific users, invite an entire domain
- [ ] email invite verification
- [ ] some kind of usage limits / AUP / rate limiting - a byte limit would satisfy my problem with nasty material
- [ ] make available in homebrew
- [ ] web site
- [ ] share with mark.dorset@... (SECRET_AUTO_ENROL="invite")
- [ ] ability to "pin" a secret - extra cost / 'pro' option - allows distribution of secrets for users

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
