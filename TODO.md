# not-so-secret TODO

## Client

## Server

- [ ] postgres backend
- [ ] email enrolment verification (if required and available with server config)
- [ ] secrt.io website.
- [ ] deploy as an actual service (kill the version running at emersion)
- [ ] invite emails
  - need to be able to invite users with a plan (encode this in a signed invite url?)
  - only send one invite email per peer per 24 hours
- [ ] quota support: daily limits, message size limits, timezone, secret linger time
- [ ] some kind of usage limits / AUP / rate limiting - a byte limit would satisfy my problem with nasty material
- [ ] make available in homebrew
- [ ] web site
- [ ] share with mark.dorset@, richard@, noel@, stephan@ ... what about the pgpkg guy?

## Future

- [ ] user-friendly support for multiple servers (eg, list endpoints and select one)
- [ ] some way to share config between devices (eg using device peer to share private key)

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
- [X] need to be able to deploy with a static config for now (secret.emersion.com)
    - [X] add SECRET_AUTO_ENROL=approve option
    - [X] when set, this should log the peerID and key to the logs so I can add it manually
- [X] static config file
    - [X] configure in deployment descriptor
    - [X] SECRET_CONFIG=/path/to/config
    - [X] make it write-protected (if it isn't)
- [X] rename "secret send" to "secret share".
- [X] split client and server into their own packages, only put main.go in cmd/secret
    - [X] rename User to server.Peer
    - [X] move the README to top-level so we can print it in the usage text too
    - [X] refactoring needed in secret.go (eg, Client struct is the config, secret.go is actually about config)
    - [X] client.go should probably be endpoint.go?
- [X] print the sent message ID to the sender so they can help the receiver
- [X] `secrt set [property]=[value]` and especially `secrt set metadata=none`
- [X] `secrt set server=https://...` set default server
- [X] `secrt set acceptNewPeers=false` stop adding peers automatically
- [X] "-f conf" should point directly to a file, not a dir. (alice.secrt, bob.secrt)
- [X] I think a missing peer on the server causes a null pointer panic
- [X] rename "secret" to "secrt"
- [X] when a file is sent, also send a filename and size
    - [X] encrypt metadata, but store it separately.
    - [X] send encrypted metadata in "secrt ls"
    - [X] optionally send a description/subject
    - [X] "secrt ls -l" should show long uuid
    - [X] create a "ls" test with acceptNewPeers=false
- [X] client-side soft limit to size of payload and metadata in envelope
- [X] server-side hard limit to size of payload and metadata in envelope
- [X] `secrt rm` to remove a secret
- [X] `secrt get -o filename` to specify where to save a file
- [X] `secrt peer ls` list peers
- [X] `secrt peer rm user@example` remove peer
- [X] `secrt peer add user@example` explicitly add a peer
- [X] GET /peer/{peer} should return JSON rather than just the public key (eg, screen name)
- [X] private key is a structure containing key type
- [X] use platform keystore to store passwords by default
- [X] platform "User" field needs to include the peerId as well as the server ID (since we can have different configs in -f)
- [X] in "secrt send", the filename should come *before* the peer address - so we can send to multiple peers
- [X] send secrets to multiple people
- [X] "secrt invite user@domain" - sends an email with download instructions
- [X] saving client config should be atomic / write to a temp file then move it.
- [X] enrolment for same peer ID and same server should require --force
- [X] enrolment should use hashcash to limit mass enrolment
- [X] verify the nonce headers on the server size
- [X] spend more time ensuring that hashcash is really working properly
