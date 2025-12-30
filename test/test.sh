#!/bin/bash

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

rm -f server.json alice/secrt.json bob/secrt.json charlie/secrt.json

secrt server &
server=$!

sleep 1

#
# Enrol alice and bob
#
echo "--- secrt enrol"
secrt -f alice/secrt.json enrol alice@example.com http://localhost:8080/
secrt -f bob/secrt.json enrol bob@example.com http://localhost:8080/

#
# Send a message from alice to bob
#
echo "--- secrt send"
MSGID=$(echo "hello" | secrt -f alice/secrt.json send -d "hello file" bob@example.com)
echo "message ID: $MSGID"

#
# Retrieve the message
#
echo "--- secrt get"
MSG=$(secrt -f bob/secrt.json get $MSGID)
echo $MSG

#
# Send a named file from bob to alice.
#
echo "--- secrt send (named)"
MSGID=$(secrt -f bob/secrt.json send alice@example.com ./README.md)

#
# Test that acceptNewPeers=false doesn't break ls.
# Enrol Charlie, but disable acceptPeers.
#
echo "--- secrt ls (acceptPeers=false)"
secrt -f charlie/secrt.json enrol charlie@example.com http://localhost:8080/
secrt -f charlie/secrt.json set acceptPeers=false
echo "hello" | secrt -f alice/secrt.json send charlie@example.com
secrt -f charlie/secrt.json ls
secrt -f charlie/secrt.json ls -l

#
# Since Charlie doesn't accept peers, he shouldn't be able to send to alice.
#
echo "--- secrt send (acceptPeers=false)"
if secrt -f alice/secrt.json send charlie@example.com ./secrt 2> /dev/null; then
  echo "secrt send should have failed!" 1>&2
  exit 1
fi

#
# Test different versions of "ls"
#
echo "--- secrt ls (variations)"
secrt -f alice/secrt.json ls
secrt -f alice/secrt.json ls -l
secrt -f alice/secrt.json ls --json


#
# Tests that secrt rm works.
#
echo "--- secrt rm"
MSGID=$(echo "msg#2" | secrt -f alice/secrt.json send bob@example.com)
secrt -f bob/secrt.json ls
secrt -f bob/secrt.json rm $MSGID

if secrt -f bob/secrt.json get $MSGID 2> /dev/null; then
  echo "secrt get should have failed (message has been deleted!)"
  exit 1
fi

if secrt -f bob/secrt.json rm xxxxxxxx 2> /dev/null; then
  echo "secrt rm should have failed"
  exit 1
fi

secrt -f bob/secrt.json ls

#
# Test that "-o name" works.
#
echo "--- secret get -o"
rm -f OUTPUT.md
MSGID=$(secrt -f bob/secrt.json send alice@example.com ./README.md)
secrt -f alice/secrt.json get -o OUTPUT.md $MSGID
if ! diff OUTPUT.md README.md > /dev/null; then
  echo "OUTPUT.md and README.md are different!" 1>&2
  exit 1
fi

#
# Secrt peer ls
#
echo "--- secret peer ls"
secrt -f alice/secrt.json peer ls

#
# Secrt peer rm
#
echo "--- secret peer rm"
secrt -f alice/secrt.json peer rm charlie@example.com
secrt -f alice/secrt.json peer ls

#
# Secrt peer add
#
secrt -f alice/secrt.json peer add charlie@example.com
secrt -f alice/secrt.json peer ls
