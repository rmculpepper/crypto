;; Copyright 2014-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide gcrypt-fetch-kdf)

(define (gcrypt-fetch-kdf factory info)
  (define spec ($get-spec info))
  (match spec
    [(list 'pbkdf2 'hmac dspec)
     (define algid (get-digest-algid dspec))
     (and algid (make-kdf info factory (gcrypt-pbkdf2-inner-impl algid)))]
    ['scrypt
     (make-kdf info factory (gcrypt-scrypt-inner-impl))]
    [(or 'argon2d 'argon2i 'argon2id)
     #:when v1.10/later?
     (make-kdf info factory (gcrypt-argon2-inner-impl))]
    [(list 'hkdf dspec)
     #:when v1.11/later?
     (match (assq dspec digests)
       [(list _ algid blocksize hmac-algid)
        (and hmac-algid (gcry_md_test_algo algid)
             (make-kdf info factory (gcrypt-hkdf-inner-impl hmac-algid)))]
       [#f #f])]
    [_ #f]))

;; ----------------------------------------

(define (gcrypt-pbkdf2-inner-impl md)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define iters (check/ref-config '(iterations) config config:pbkdf2-kdf #:in kdfi))
     (gcry_kdf_derive pass GCRY_KDF_PBKDF2 md salt iters key-size))))

(define (gcrypt-scrypt-inner-impl)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (N ln p r)
       (check/ref-config '(N ln p r) config config:scrypt-kdf #:in kdfi))
     (define N* (or N (expt 2 ln)))
     (unless (equal? r 8)
       (impl-limit-error "r parameter must be 8\n  given: ~e" r #:in kdfi))
     (gcry_kdf_derive pass GCRY_KDF_SCRYPT N* salt p key-size))))

;; ----------------------------------------
;; KDFs using new (1.10) KDF API

(define (gcrypt-kdf algo subalgo
                    #:length outlen
                    #:params params
                    #:input [input #f]
                    #:salt [salt #f]
                    #:key [key #f]
                    #:ad [ad #f])
  (define ctx (gcry_kdf_open algo subalgo params
                             input (bytes-length input)
                             salt (if salt (bytes-length salt) 0)
                             key (if key (bytes-length key) 0)
                             ad (if ad (bytes-length ad) 0)))
  (gcry_kdf_compute ctx)
  (define outbuf (make-bytes outlen))
  (gcry_kdf_final ctx outlen outbuf)
  (gcry_kdf_close ctx)
  outbuf)

(define (gcrypt-argon2-inner-impl)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (t m p v)
       (check/ref-config '(t m p v) config config:argon2-kdf #:in kdfi))
     (unless (eqv? v 19)
       (crypto-error "argon2 version unsupported\n  version: ~e"
                     v #:in kdfi))
     ;; Note: requires non-empty salt
     (gcrypt-kdf GCRY_KDF_ARGON2
                 (case ($get-spec kdfi)
                   [(argon2d) GCRY_KDF_ARGON2D]
                   [(argon2i) GCRY_KDF_ARGON2I]
                   [(argon2id) GCRY_KDF_ARGON2ID])
                 #:length key-size
                 #:params (list key-size t m p)
                 #:input pass
                 #:salt salt
                 #:key #""
                 #:ad #""))))

(define (gcrypt-hkdf-inner-impl mac-algo)
  (make-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     ;; Note: requires non-empty pass
     (gcrypt-kdf GCRY_KDF_HKDF mac-algo
                 #:length key-size
                 #:params (list key-size)
                 #:input pass
                 #:salt #f
                 #:key salt
                 #:ad info))))

;; GCRY_KDF_ONESTEP_KDF_MAC -- requires non-empty pass, info (ad)
;; GCRY_KDF_ONESTEP_KDF_MAC -- requires non-empty pass, key, info (ad)
;; GCRY_KDF_X963_KDF        -- requires non-empty pass
