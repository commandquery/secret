# secrt.io

Secrt is a simple command-line utility that helps technical folk securely share secrets with peers,
coworkers and devices using end-to-end encryption.

Secrt uses X25519-XSalsa20-Poly1305 (NaCl box) public-key authenticated encryption via the
Go package [golang.org/x/crypto/nacl/box](https://pkg.go.dev/golang.org/x/crypto/nacl/box).

## Examples

You can use secrt to send anything at all from the command line; for example:

* tokens
* passwords
* reset links
* config files
* api keys
* connection strings
* private keys
* certificates
* credentials
* PATs
* ssh keys
* license keys
* session cookies

## How to use it

Download the binary:

    brew install secrt

Generate and share your public key:

    secrt enrol me@example.com

Invite a friend to enrol:

    secrt invite friend@example.com

Send them a secret!

    echo “p4ssw0rd” | secrt share friend@example.com

See what secrets have been sent to you:

    secrt ls

Download and decrypt a secret:

    secrt get 0d89289f > config.yaml

## Devices

You can use secrt to securely share secrets across devices and other objects using subaccounts.
Simply log into the device and enrol it:

    secrt enrol me@example.com/device.name

This creates a private key for that device, under your account. Now you can easily
share secrets with it.

The nice thing about using secrt on devices is that you don’t have to think about where you’re
going to put the secrets. Share the secret from your laptop, navigate to the right place in the device,
then drop the secret into `$PWD`.

## Limitations

Secrets are limited to 50KB (that’s a big key!)
Secrets are permanently deleted after 24 hours
Acceptable use policy applies
20 secrets/day on the free plan (??)


