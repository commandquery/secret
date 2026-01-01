#!/bin/bash
#
# TODO
# Write assertions for the test results!

#
# Basic setup and start server
#
PATH=.:$PATH

set -e

cleanup() {
    kill "$server" 2>/dev/null
}
trap cleanup EXIT

go build -o secrt ../cmd/secrt
go test ..

rm -f *.json

# Use a small challenge size to keep tests snappy.
export SECRT_CHALLENGE_SIZE=10
secrt server &
server=$!

sleep 1

#
# Enrol alice and bob
#
echo "--- secrt enrol"
secrt -c alice.json enrol --store=clear alice@example.com http://localhost:8080/
secrt -c bob.json enrol --store=clear bob@example.com http://localhost:8080/

#
# Send a message from alice to bob
#
echo "--- secrt send"
MSGID=$(echo "hello" | secrt -c alice.json send -d "hello file" bob@example.com)
echo "message ID: $MSGID"

#
# Retrieve the message
#
echo "--- secrt get"
MSG=$(secrt -c bob.json get $MSGID)
echo $MSG

#
# Send a named file from bob to alice.
#
echo "--- secrt send (named)"
MSGID=$(secrt -c bob.json send ./TEST.md alice@example.com)

#
# Test that acceptNewPeers=false doesn't break ls.
# Enrol Charlie, but disable acceptPeers.
#
echo "--- secrt ls (acceptPeers=false)"
secrt -c charlie.json enrol --store=clear charlie@example.com http://localhost:8080/
secrt -c charlie.json set acceptPeers=false
ALICEMSG=$(echo "hello" | secrt -c alice.json send charlie@example.com)
secrt -c charlie.json ls
secrt -c charlie.json ls -l

#
# Since Charlie doesn't accept peers, she shouldn't be able to send to alice.
#
echo "--- secrt send (acceptPeers=false)"
if secrt -c alice.json send ./secrt charlie@example.com 2> /dev/null; then
  echo "secrt send should have failed!" 1>&2
  exit 1
fi

#
# Since Charlie doesn't accept peers, she shouldn't be able to receive from alice.
#
echo "--- secrt get (acceptPeers=false)"
if secrt -c charlie.json get $ALICEMSG 2> /dev/null; then
  echo "secrt get should have failed!" 1>&2
  exit 1
fi

#
# Test different versions of "ls"
#
echo "--- secrt ls (variations)"
secrt -c alice.json ls
secrt -c alice.json ls -l
secrt -c alice.json ls --json


#
# Tests that secrt rm works.
#
echo "--- secrt rm"
MSGID=$(echo "msg#2" | secrt -c alice.json send bob@example.com)
secrt -c bob.json ls
secrt -c bob.json rm $MSGID

if secrt -c bob.json get $MSGID 2> /dev/null; then
  echo "secrt get should have failed (message has been deleted!)"
  exit 1
fi

if secrt -c bob.json rm xxxxxxxx 2> /dev/null; then
  echo "secrt rm should have failed"
  exit 1
fi

secrt -c bob.json ls

#
# Test that "-o name" works.
#
echo "--- secret get -o"
rm -f OUTPUT.md
MSGID=$(secrt -c bob.json send ./TEST.md alice@example.com)
secrt -c alice.json get -o OUTPUT.md $MSGID
if ! diff OUTPUT.md TEST.md > /dev/null; then
  echo "OUTPUT.md and TEST.md are different!" 1>&2
  exit 1
fi

#
# Secrt peer ls
#
echo "--- secret peer ls"
secrt -c alice.json peer ls

#
# Secrt peer rm
#
echo "--- secret peer rm"
secrt -c alice.json peer rm charlie@example.com
secrt -c alice.json peer ls

#
# Secrt peer add
#
echo "--- secret peer add"
secrt -c alice.json peer add charlie@example.com
secrt -c alice.json peer ls

#
# Test platform keystore create
#
echo "--- enrol with platform keystore"
secrt -c denise.json enrol --store=platform denise@example.com http://localhost:8080/

#
# Test platform keystore access
#
echo "--- send with platform keystore"
MSGID=$(echo "platform keystore" | secrt -c denise.json send alice@example.com)
MSG=$(secrt -c alice.json get $MSGID)

#
# Test the default keystore type is "platform"
#
echo "--- default keystore type"
secrt -c ernie.json enrol ernie@example.com http://localhost:8080/
if ! jq -e '.endpoints[0].privateKeyStores | map(select(.type == "platform")) | length == 1' ernie.json > /dev/null; then
  echo "unexpected keystore type in ernie.json, expected default to be 'platform'"
  exit 1
fi

#
# Send to multiple users
#
echo "--- secrt send multiple"
secrt -c alice.json send ./TEST.md bob@example.com charlie@example.com denise@example.com ernie@example.com

#
# Send to multiple users (with an error)
#
echo "--- secrt send multiple - error check"
if secrt -c alice.json send ./TEST.md bob@example.com charlie@example.com denise@example.com error@example.com 2> /dev/null; then
  echo "secrt send to nobody@example.com should have failed!" 2>&1
  exit 1
fi

#
# Test sending an invite
#
echo "--- secrt invite user"
secrt -c alice.json invite fred@example.com

#
# Attempt to double enrol without --force
#
echo "--- secrt double enrol fail test"
secrt -c guy.json enrol guy@example.com http://localhost:8080/
if secrt -c guy.json enrol guy@example.com http://localhost:8080/ 2> /dev/null; then
  echo "secrt enrol should have failed!" 2>&1
  exit 1
fi

#
# Attempt to enrol on same server with different peer ID
#
echo "--- secrt same server different peer"
secrt -c guy.json enrol harry@example.com http://localhost:8080/

#
# Test that the default endpoint changes
#
echo "--- secrt send from harry using guy.json default server"
echo "hello" | secrt -c guy.json send alice@example.com
secrt -c alice.json ls

#
# Attempt to double enrol with --force
# FIXME: this won't work until we have a reenrolment flow on the server side
#
#echo "--- secrt double enrol --force"
#secrt -c guy.json enrol --force guy@example.com http://localhost:8080/
