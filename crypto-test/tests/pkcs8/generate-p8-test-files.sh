#!/bin/bash

# Script for generating test files w/ password = "password"
# requires openssl >= 1.1.0

openssl genrsa -out rsa.pem 512
openssl pkcs8 -topk8 -in rsa.pem -outform PEM -out rsa.p8.pem -nocrypt
openssl pkcs8 -topk8 -in rsa.pem -outform DER -out rsa.der -nocrypt

P8ARGS="-topk8 -in rsa.pem -outform DER -passout pass:password"
openssl pkcs8 $P8ARGS -out rsa.des3-sha1.p8 -v2 des3
openssl pkcs8 $P8ARGS -out rsa.aes128-sha1.p8 -v2 aes128
openssl pkcs8 $P8ARGS -out rsa.aes128-sha256.p8 -v2 aes128 -v2prf hmacWithSHA256
openssl pkcs8 $P8ARGS -out rsa.aes128-scrypt.p8 -v2 aes128 -scrypt
