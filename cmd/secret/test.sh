#!/bin/bash

cleanup() {
    kill "$server" 2>/dev/null
}
trap cleanup EXIT

go build -o secret .

rm -f server.json test/alice/keys test/bob/keys

./secret server &
server=$!

./secret -f test/alice init alice@example.com http://localhost:8080/
./secret -f test/bob init bob@example.com http://localhost:8080/