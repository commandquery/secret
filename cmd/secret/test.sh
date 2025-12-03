#!/bin/bash

# Test the encryption process.

set -ex

go build
rm -rf test

# Create test stores for the various users.
mkdir -p test/alice
mkdir -p test/bob
mkdir -p test/kpop

#
# create keys for the different people
#
./secret -f test/alice init alice@example.io
./secret -f test/alice key -n > test/alice.pub
./secret -f test/bob init bob@example.io
./secret -f test/bob key -n > test/bob.pub

#
# Mutual key exchange
#
./secret -f test/alice add bob@example.io < test/bob.pub
./secret -f test/bob add alice@example.io < test/alice.pub


#
# Create a random file that we want to encrypt.
#
head -c2048 /dev/random | base64 | fold > test/payload.txt

#
# Send a file from alice to bob
#
./secret -f test/alice send bob@example.io test/payload.txt > test/payload.pub
./secret -f test/bob decrypt alice@example.io test/payload.pub > test/payload.rec
diff -u test/payload.txt test/payload.rec

#
# Save the file and pull it out again (both are crypto ops)
#
./secret -f test/bob save alice@example.io test test/payload.pub
./secret -f test/bob cat test > test/payload.got
diff -u test/payload.txt test/payload.got

./secret -f test/bob ls
./secret -f test/bob rm test
./secret -f test/bob ls

./secret -f test/bob topic-key dev certificate.test 1

