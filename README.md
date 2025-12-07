# Secret: Securely send and store data over plaintext channels

Secret is a simple command for exchanging sensitive data with your peers using
end-to-end encryption. Encrypted messages are stored temporarily on a server until
the peer picks them up.

General usage:

    secret [options] command ...

Options:
    -f <secretdir>               - store (and retrieve) configuration from this directory

Commands:
    init [--force] <id>          - create (or replace) your public key and your ID.
    send <peerID>                - send stdin to the given peer.
    ls                           - list messages waiting for you
    get <msgid>                  - show the message with ID msgid.