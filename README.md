# secret

This is the Git documentation for secret. Usage can be found in [USAGE.md].

## Enrolment Challenge

Most HTTP endpoints are authenticated, but the enrolment API is not, and this is a problem
because an obvious way to share CSAM is just to enrol a bunch of accounts and send partial
messages over them, basically abusing the free tier.

To avoid this, we create friction by requiring a HashCash challenge on the public API endpoints.

The enrolment process works as follows:

- Client generates a (public, private) keypair
- Requests a challenge by posing the public key to the server
- Server responds with 