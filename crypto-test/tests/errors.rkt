;; Copyright 2018-2022 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require crypto
         crypto/libcrypto
         checkers)

;; SETUP

;; libcrypto is generally available
(crypto-factories libcrypto-factory)

;; ============================================================
;; Digests

(test #:name "digests"
  (check (digest 'tiger1 #"hello world")
         #:error #rx"could not get implementation")

  (check (digest 'sha256 #"hello world" #:key #"abc")
         #:error #rx"bad key size\n  given: 3 bytes")

  (check (let ([ctx (make-digest-ctx 'sha256)])
           (digest-final ctx)
           (digest-update ctx #"hello"))
         #:error #rx"wrong state\n  state: closed"))

;; ============================================================
;; Ciphers

(define ctr (get-cipher '(aes ctr)))
(define gcm (get-cipher '(aes gcm)))
(define key16 (crypto-random-bytes 16))
(define iv16   (crypto-random-bytes 16))
(define iv12   (crypto-random-bytes 12))

(test #:name "ciphers"
  (check (encrypt ctr #"short" iv16 #"the message")
         #:error #rx"bad key size for cipher.*given: 5 bytes\n")

  (check (encrypt ctr key16 #"short" #"the message")
         #:error #rx"bad IV size for cipher.*given: 5 bytes\n")

  (check (encrypt gcm key16 iv12 #"the message" #:auth-size 2)
         #:error #rx"bad authentication tag size.*given: 2 bytes")

  (check (let ([ctx (make-encrypt-ctx ctr key16 iv16)])
           (cipher-final ctx)
           (cipher-update ctx #"hello"))
         #:error #rx"wrong state\n  state: closed")

  (check (let ([ctx (make-encrypt-ctx gcm key16 iv12)])
           (cipher-update ctx #"hello")
           (cipher-update-aad ctx #"world"))
         #:error #rx"wrong state\n  state: ready for input")

  (check (let ([ctx (make-encrypt-ctx gcm key16 iv12)])
           (cipher-final ctx (make-bytes 12)))
         #:error #rx"cannot set authentication tag for encryption context")
  (check (let ([ctx (make-decrypt-ctx gcm key16 iv12)])
           (cipher-final ctx #""))
         #:error #rx"cannot set authentication tag for decryption context with attached tag")
  (check (let ([ctx (make-decrypt-ctx gcm key16 iv12 #:auth-attached? #f)])
           (cipher-final ctx #"abc"))
         #:error #rx"wrong size for authentication tag.*given: 3 bytes")
  (check (let ()
           (define cmsg (encrypt gcm key16 iv12 #"message"))
           (define ctx (make-decrypt-ctx gcm key16 iv12))
           (cipher-update ctx cmsg)
           (cipher-final ctx)
           (cipher-get-auth-tag ctx))
         #:error #rx"cannot get authentication tag for decryption context")

  (check (encrypt '(aes ecb) key16 #f #"short" #:pad #f)
         #:error #rx"input size not a multiple of block size")

  (check (decrypt '(aes ecb) key16 #f #"short" #:pad #f)
         #:error #rx"input size not a multiple of block size"))

;; ============================================================
;; KDF

(test #:name "kdf"
  (check (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '((sparkles 10)))
         #:error #rx"unsupported option for PBKDF2\n  option: 'sparkles")

  (check (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '())
         #:error #rx"missing required option for PBKDF2\n  option: 'iterations")

  (when (get-kdf 'scrypt)
    (check (kdf 'scrypt #"pass" #"salt" `((N ,(expt 2 16)) (ln 16) (r 8) (p 1)))
           #:error #rx"conflicting options for scrypt\n  options: 'N and 'ln")))

;; ============================================================
;; PK

(test #:name "pk"
  (check (generate-pk-parameters 'rsa '())
         #:error #rx"parameters not supported")

  (define rsapriv (generate-private-key 'rsa '((nbits 512))))
  (define rsapub (pk-key->public-only-key rsapriv))

  (check (digest/sign rsapub 'sha1 #"hello world")
         #:error #rx"contract violation\n  expected: private-key[?]")

  (check (pk-derive-secret rsapriv rsapub)
         #:error #rx"key agreement not supported")

  (define ecpriv (generate-private-key 'ec '((curve secp256r1))))
  (define ecpub (pk-key->public-only-key ecpriv))

  (check (pk-encrypt ecpub #"secret")
         #:error #rx"encrypt/decrypt not supported")

  (define ecxpriv (generate-private-key 'ecx '((curve x25519))))
  (define ecxpub (pk-key->public-only-key ecxpriv))

  (check (pk-encrypt ecxpub #"secret")
         #:error #rx"encrypt/decrypt not supported")
  (check (pk-sign ecxpriv #"message")
         #:error #rx"sign/verify not supported")

  (check (digest/sign ecpriv 'sha1 #"hello world" #:pad 'pkcs1-v1.5)
         #:error #rx"sign/verify padding not supported\n  padding: 'pkcs1-v1.5")
  (check (pk-sign-digest rsapriv 'sha256 (digest 'sha1 #"message"))
         #:error #rx"wrong size for digest\n  expected: 32 bytes\n  given: 20 bytes")

  (check (pk-derive-secret ecxpriv ecpub)
         #:error #rx"peer key has different implementation.*\n  peer: "))
