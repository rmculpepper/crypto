;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide sodium-fetch-kdf)

(define (sodium-fetch-kdf factory info)
  (define spec ($get-spec info))
  (define inner
    (case spec
      [(argon2i) (and argon2i-ok? (sodium-argon2-inner-impl spec))]
      [(argon2id) (and argon2id-ok? (sodium-argon2-inner-impl spec))]
      [(scrypt) (and scrypt-ok? (sodium-scrypt-inner-impl))]
      [else #f]))
  (make-kdf info factory inner))

;; ----------------------------------------

(define (sodium-argon2-inner-impl spec)
  (define (get-alg)
    (case spec
      [(argon2i) crypto_pwhash_ALG_ARGON2I13]
      [(argon2id) crypto_pwhash_ALG_ARGON2ID13]))
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (t mkb p)
       (check/ref-config '(t m p) config config:argon2-kdf #:in kdfi))
     (unless (equal? p 1)
       (impl-limit-error "parallelism parameter must be 1\n  given: ~e"
                         p #:in kdfi))
     (define m (* mkb 1024))
     (unless (= (bytes-length salt) crypto_pwhash_argon2id_SALTBYTES)
       (impl-limit-error "salt must be ~s bytes\n  given: ~s bytes"
                         crypto_pwhash_argon2id_SALTBYTES (bytes-length salt) #:in kdfi))
     (define out (make-bytes key-size))
     (define alg (get-alg))
     (define status (crypto_pwhash out key-size pass (bytes-length pass) salt t m alg))
     (unless (zero? status) (crypto-error "key derivation failed" #:in kdfi))
     out)
   (lambda (kdfi config pass)
     (define-values (t mkb p)
       (check/ref-config '(t m p) config config:argon2-base #:in kdfi))
     (unless (equal? p 1)
       (impl-limit-error "parallelism parameter must be 1\n  given: ~e"
                         p #:in kdfi))
     (define m (* 1024 mkb))
     (define alg (get-alg))
     (define out (make-bytes (crypto_pwhash_strbytes)))
     (define status (crypto_pwhash_str_alg out pass (bytes-length pass) t m alg))
     (unless (zero? status) (crypto-error "failed: ~e" status #:in kdfi))
     (cast out _bytes _string/latin-1))
   (lambda (kdfi pass cred)
     (check-pwhash/kdf-spec cred spec)
     (define status (crypto_pwhash_str_verify cred pass (bytes-length pass)))
     (if (zero? status) 'valid 'invalid))))

(define (sodium-scrypt-inner-impl)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (N ln p r)
       (check/ref-config '(N ln p r) config config:scrypt-kdf #:in kdfi))
     (define N* (or N (expt 2 ln)))
     (define out (make-bytes key-size))
     (define status
       (crypto_pwhash_scryptsalsa208sha256_ll pass (bytes-length pass)
                                              salt (bytes-length salt)
                                              N r p
                                              out key-size))
     (unless (zero? status) (crypto-error "key derivation failed" #:in kdfi))
     out)))
