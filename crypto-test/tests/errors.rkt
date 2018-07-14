#lang racket/base
(require crypto
         crypto/libcrypto
         rackunit)

;; SETUP

;; libcrypto is generally available
(crypto-factories libcrypto-factory)

;; ============================================================
;; Digests

(check-exn #rx"could not get implementation"
           (lambda () (digest 'tiger1 #"hello world")))

(check-exn #rx"bad key size\n  given: 3 bytes"
           (lambda () (digest 'sha256 #"hello world" #:key #"abc")))

(check-exn #rx"wrong state\n  state: closed"
           (lambda ()
             (define ctx (make-digest-ctx 'sha256))
             (digest-final ctx)
             (digest-update ctx #"hello")))

;; ============================================================
;; Ciphers

(define ctr (get-cipher '(aes ctr)))
(define gcm (get-cipher '(aes gcm)))
(define key16 (crypto-random-bytes 16))
(define iv16   (crypto-random-bytes 16))
(define iv12   (crypto-random-bytes 12))

(check-exn #rx"bad key size for cipher.*given: 5 bytes\n"
           (lambda () (encrypt ctr #"short" iv16 #"the message")))

(check-exn #rx"bad IV size for cipher.*given: 5 bytes\n"
           (lambda () (encrypt ctr key16 #"short" #"the message")))

(check-exn #rx"bad authentication tag size.*given: 2 bytes"
           (lambda () (encrypt gcm key16 iv12 #"the message" #:auth-size 2)))

(check-exn #rx"wrong state\n  state: closed"
           (lambda ()
             (define ctx (make-encrypt-ctx ctr key16 iv16))
             (cipher-final ctx)
             (cipher-update ctx #"hello")))

(check-exn #rx"wrong state\n  state: ready for input"
           (lambda ()
             (define ctx (make-encrypt-ctx gcm key16 iv12))
             (cipher-update ctx #"hello")
             (cipher-update-aad ctx #"world")))

(check-exn #rx"cannot set authentication tag for encryption context"
           (lambda ()
             (define ctx (make-encrypt-ctx gcm key16 iv12))
             (cipher-final ctx (make-bytes 12))))
(check-exn #rx"cannot set authentication tag for decryption context with attached tag"
           (lambda ()
             (define ctx (make-decrypt-ctx gcm key16 iv12))
             (cipher-final ctx #"")))
(check-exn #rx"wrong size for authentication tag.*given: 3 bytes"
           (lambda ()
             (define ctx (make-decrypt-ctx gcm key16 iv12 #:auth-attached? #f))
             (cipher-final ctx #"abc")))
(check-exn #rx"cannot get authentication tag for decryption context"
           (lambda ()
             (define cmsg (encrypt gcm key16 iv12 #"message"))
             (define ctx (make-decrypt-ctx gcm key16 iv12))
             (cipher-update ctx cmsg)
             (cipher-final ctx)
             (cipher-get-auth-tag ctx)))

(check-exn #rx"input size not a multiple of block size"
           (lambda () (encrypt '(aes ecb) key16 #f #"short" #:pad #f)))

(check-exn #rx"input size not a multiple of block size"
           (lambda () (decrypt '(aes ecb) key16 #f #"short" #:pad #f)))

;; ============================================================
;; KDF

(check-exn #rx"unsupported option for PBKDF2\n  option: 'sparkles"
           (lambda () (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '((sparkles 10)))))

(check-exn #rx"missing required option for PBKDF2\n  option: 'iterations"
           (lambda () (kdf '(pbkdf2 hmac sha1) #"pass" #"salt" '())))

(when (get-kdf 'scrypt)
  (check-exn #rx"conflicting options for scrypt\n  options: 'N and 'ln"
             (lambda () (kdf 'scrypt #"pass" #"salt" `((N ,(expt 2 16)) (ln 16) (r 8) (p 1))))))

;; ============================================================
;; PK

(check-exn #rx"parameters not supported"
           (lambda () (generate-pk-parameters 'rsa '())))

(define rsapriv (generate-private-key 'rsa '((nbits 512))))
(define rsapub (pk-key->public-only-key rsapriv))

(check-exn #rx"contract violation\n  expected: private-key[?]"
           (lambda () (digest/sign rsapub 'sha1 #"hello world")))

(check-exn #rx"key agreement not supported"
           (lambda () (pk-derive-secret rsapriv rsapub)))

(define ecpriv (generate-private-key 'ec '((curve secp256r1))))
(define ecpub (pk-key->public-only-key ecpriv))

(check-exn #rx"encrypt/decrypt not supported"
           (lambda () (pk-encrypt ecpub #"secret")))

(define ecxpriv (generate-private-key 'ecx '((curve x25519))))
(define ecxpub (pk-key->public-only-key ecxpriv))

(check-exn #rx"encrypt/decrypt not supported"
           (lambda () (pk-encrypt ecxpub #"secret")))
(check-exn #rx"sign/verify not supported"
           (lambda () (pk-sign ecxpriv #"message")))

(check-exn #rx"sign/verify padding not supported\n  padding: 'pkcs1-v1.5"
           (lambda () (digest/sign ecpriv 'sha1 #"hello world" #:pad 'pkcs1-v1.5)))
(check-exn #rx"wrong size for digest\n  expected: 32 bytes\n  given: 20 bytes"
           (lambda () (pk-sign-digest rsapriv 'sha256 (digest 'sha1 #"message"))))

(check-exn #rx"peer key has different implementation\n  peer: "
           (lambda () (pk-derive-secret ecxpriv ecpub)))
