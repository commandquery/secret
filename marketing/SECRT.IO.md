# Introduction

Hi Claude. The following instructions contain an outline for a website for my new product, `secrt`. I'd like you to
build the web site for me.

The website should be attractive, but minimal, and use fonts and colours appropriate for a technical
audience who is looking to download a CLI tool (ie: system administrators). The website should automatically support
light and dark mode.

Please don't editorialise the text. Instead, focus on the HTML, CSS and (if necessary) any JavaScript.
You can use Tailwind CSS, if doing so makes sense. You can use VueJS if you need to, but I'd prefer to avoid
any frameworks.

The rest of this document contains the layout of the landing page. Your job is to style this in an attractive way.
I've included further instructions and hints using HTML comments within the Markdown below. These hints should be
used as guidance, and should not appear in the final document.

You are welcome to point out any typos or incorrect assertions.

It's important that the HTML and CSS be readable and editable by myself when it's time to add new features
or documentation.

Here we go!

# secrt.io

`secrt` is a simple command-line utility that helps technical folk securely share secrets and config
files with peers, coworkers and devices using end-to-end encryption.

`secrt` uses X25519-XSalsa20-Poly1305 (NaCl box) public-key authenticated end-to-end encryption
via the Go package [golang.org/x/crypto/nacl/box](https://pkg.go.dev/golang.org/x/crypto/nacl/box).

`secrt` uses a server to share public keys and forward messages, but your private key never leaves
your device, and the server is unable to read your messages.

`secrt` is for sharing secrets; it's not a file-sharing service. Shared secrets are limited to 50KB and
are retained for a maximum of 24 hours.

## Examples

<!--
  The following is a list of use cases for secrt.io. I like the idea of these being presented in a scrolling
  terminal or other simple animation, using a `secrt send` visual device, for example, `secrt send token.yaml coworker@example.com`.
  You could come up with a few different email addresses like "peer@example.com", "housemate@example.com",
  etc, and mix up the use cases, so for example `secrt send <randomaddress> <randomusecasefilename>`
-->

send secrets from your command line.

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

<!--
    This might be best presented in something resembling a terminal window, with comments
    for the body text, and the commands presented as if entered into a shell prompt.
-->

Generate and share your public key:

    $ secrt enrol me@example.com
    enrolment completed

Invite a friend to enrol:

    $ secrt invite friend@example.com
    invitation sent

Send them a secret!

    $ echo “p4ssw0rd” | secrt send friend@example.com
    2465b56c

See what secrets have been sent to you:

    $ secrt ls
    ID       Peer                       Size Sent       Description
    cbf061e6 alice@example.com           859 10:01:41   README.md

Download and decrypt a secret:

    $ secrt get cbf061e6 > README.md

## Downloading

<!--
    this should include tabs for MacOS, Windows and Linux, with curl commands to https://github.com/commandquery/secrt/releases
    I'll fill in the details later. If you have typical download suggestions for Windows in particular, please include them and I'll
    do my best to support it.
-->

## Limitations

Secrets are limited to 50KB (that’s a big key!)
Secrets are permanently deleted after 24 hours
Acceptable use policy applies

