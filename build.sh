#!/bin/bash

if [ -e sha1.o ]
then
  rm -f ./vectors
  ./gentests.pl > tests.c
  gcc -O0 -g -Wall -Wextra -pedantic -DUSE_SHA1 -DTEST_VECTORS pkcs1.c pss-vect.c sha1.o -o vectors -lgmp && ./vectors
  # TODO: try to automate valgrind & memwatch tests below
else
  echo "SHA1 code not present, skipping verification of EMSA-PSS test vectors"
fi

if [ -e testkey.pem ]
then
  gcc -O0 -g -Wall -Wextra -pedantic pk2db.c -o pk2db -lsqlite3 -lssl
  rm -f testkey.db && ./pk2db testkey.pem testkey.db testkey
else
  echo "pk2db cannot run: please generate a test key with openssl"
fi
