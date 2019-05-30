#lang racket/base
(require crypto
         crypto/libcrypto
         checktest)

;; SETUP

;; libcrypto is generally available
(crypto-factories libcrypto-factory)

;; ============================================================
;; Digests

(test
  (check-raise (digest 'tiger1 #"hello world")
               #rx"could not get implementation")
  (check-raise (digest 'sha256 #"hello world" #:key #"abc")
               #rx"bad key size\n  given: 3 bytes")
  (check-raise (let ()
                 (define ctx (make-digest-ctx 'sha256))
                 (digest-final ctx)
                 (digest-update ctx #"hello"))
               #rx"wrong state\n  state: closed"))

;; ============================================================
;; Ciphers

(test
  (define ctr (get-cipher '(aes ctr)))
  (define gcm (get-cipher '(aes gcm)))
  (define key16 (crypto-random-bytes 16))
  (define iv16   (crypto-random-bytes 16))
  (define iv12   (crypto-random-bytes 12))

  (check-raise (encrypt ctr #"short" iv16 #"the message")
               #rx"bad key size for cipher.*given: 5 bytes\n")
  (check-raise (encrypt ctr key16 #"short" #"the message")
               #rx"bad IV size for cipher.*given: 5 bytes\n")
  (check-raise (encrypt gcm key16 iv12 #"the message" #:auth-size 2)
               #rx"bad authentication tag size.*given: 2 bytes")
  (check-raise (let ()
                 (define ctx (make-encrypt-ctx ctr key16 iv16))
                 (cipher-final ctx)
                 (cipher-update ctx #"hello"))
               #rx"wrong state\n  state: closed")
  (check-raise (let ()
                 (define ctx (make-encrypt-ctx gcm key16 iv12))
                 (cipher-update ctx #"hello")
                 (cipher-update-aad ctx #"world"))
               #rx"wrong state\n  state: ready for input")
  (check-raise (let ()
                 (define ctx (make-encrypt-ctx gcm key16 iv12))
                 (cipher-final ctx (make-bytes 12)))
               #rx"cannot set authentication tag for encryption context")
  (check-raise (let ()
                 (define ctx (make-decrypt-ctx gcm key16 iv12))
                 (cipher-final ctx #""))
               #rx"cannot set authentication tag for decryption context with attached tag")
  (check-raise (let ()
                 (define ctx (make-decrypt-ctx gcm key16 iv12 #:auth-attached? #f))
                 (cipher-final ctx #"abc"))
               #rx"wrong size for authentication tag.*given: 3 bytes")
  (check-raise (let ()
                 (define cmsg (encrypt gcm key16 iv12 #"message"))
                 (define ctx (make-decrypt-ctx gcm key16 iv12))
                 (cipher-update ctx cmsg)
                 (cipher-final ctx)
                 (cipher-get-auth-tag ctx))
               #rx"cannot get authentication tag for decryption context")
  (check-raise (encrypt '(aes ecb) key16 #f #"short" #:pad #f)
               #rx"input size not a multiple of block size")
  (check-raise (decrypt '(aes ecb) key16 #f #"short" #:pad #f)
               #rx"input size not a multiple of block size"))

;; ============================================================
;; KDF

(test
  (check-raise (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '((sparkles 10)))
               #rx"unsupported option for PBKDF2\n  option: 'sparkles")
  (check-raise (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '())
               #rx"missing required option for PBKDF2\n  option: 'iterations")
  (when (get-kdf 'scrypt)
    (check-raise (kdf 'scrypt #"pass" #"salt" `((N ,(expt 2 16)) (ln 16) (r 8) (p 1)))
                 #rx"conflicting options for scrypt\n  options: 'N and 'ln")))

;; ============================================================
;; PK

(test
  (test
    (check-raise (generate-pk-parameters 'rsa '())
                 #rx"parameters not supported"))
  (test
    (define rsapriv (generate-private-key 'rsa '((nbits 512))))
    (define rsapub (pk-key->public-only-key rsapriv))
    (check-raise (digest/sign rsapub 'sha1 #"hello world")
                 #rx"contract violation\n  expected: private-key[?]")
    (check-raise (pk-derive-secret rsapriv rsapub)
                 #rx"key agreement not supported")
    (check-raise (pk-sign-digest rsapriv 'sha256 (digest 'sha1 #"message"))
                 #rx"wrong size for digest\n  expected: 32 bytes\n  given: 20 bytes"))
  (test
    (define ecpriv (generate-private-key 'ec '((curve secp256r1))))
    (define ecpub (pk-key->public-only-key ecpriv))
    (check-raise (pk-encrypt ecpub #"secret")
                 #rx"encrypt/decrypt not supported")
    (check-raise (digest/sign ecpriv 'sha1 #"hello world" #:pad 'pkcs1-v1.5)
                 #rx"sign/verify padding not supported\n  padding: 'pkcs1-v1.5"))
  (test
    (define ecxpriv (generate-private-key 'ecx '((curve x25519))))
    (define ecxpub (pk-key->public-only-key ecxpriv))
    (check-raise (pk-encrypt ecxpub #"secret")
                 #rx"encrypt/decrypt not supported")
    (check-raise (pk-sign ecxpriv #"message")
                 #rx"sign/verify not supported"))
  (test
    (define ecpriv (generate-private-key 'ec '((curve secp256r1))))
    (define ecpub (pk-key->public-only-key ecpriv))
    (define ecxpriv (generate-private-key 'ecx '((curve x25519))))
    (define ecxpub (pk-key->public-only-key ecxpriv))
    (check-raise (pk-derive-secret ecxpriv ecpub)
                 #rx"peer key has different implementation\n  peer: ")))
