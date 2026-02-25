;; Copyright 2014-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define gcrypt-pbkdf2-impl%
  (class kdf-impl-base%
    (init-field di)
    (inherit-field spec)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (iters key-size)
        (check/ref-config '(iterations key-size) config config:pbkdf2-kdf "PBKDF2"))
      (define md (get-field md di))
      (gcry_kdf_derive pass GCRY_KDF_PBKDF2 md salt iters key-size))

    (define/override (pwhash config pass)
      (kdf-pwhash-pbkdf2 this spec config pass))
    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))
    ))

(define gcrypt-scrypt-impl%
  (class kdf-impl-base%
    (inherit about)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (N ln p r key-size)
        (check/ref-config '(N ln p r key-size) config config:scrypt-kdf "scrypt"))
      (define N* (or N (expt 2 ln)))
      (unless (equal? r 8)
        (impl-limit-error "r parameter must be 8\n  given: ~e\n  in: ~a" r (about)))
      (gcry_kdf_derive pass GCRY_KDF_SCRYPT N* salt p key-size))

    (define/override (pwhash config pass)
      (kdf-pwhash-scrypt this config pass))
    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))
    ))

;; ----------------------------------------

;; Base class for KDFs using new (1.10) KDF API.
(define gcrypt-kdf-impl-base%
  (class kdf-impl-base%
    (super-new)

    (define/public (do-kdf algo subalgo
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
    ))

(define gcrypt-argon2-impl%
  (class gcrypt-kdf-impl-base%
    (inherit do-kdf)
    (inherit-field spec)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (t m p v key-size)
        (check/ref-config '(t m p v key-size) config config:argon2-kdf "Argon2"))
      ;; (unless (eqv? v #x13) __)
      ;; Note: requires non-empty salt
      (do-kdf GCRY_KDF_ARGON2
              (case spec
                [(argon2d) GCRY_KDF_ARGON2D]
                [(argon2i) GCRY_KDF_ARGON2I]
                [(argon2id) GCRY_KDF_ARGON2ID])
              #:length key-size
              #:params (list key-size t m p)
              #:input pass
              #:salt salt
              #:key #""
              #:ad #""))

    (define/override (pwhash config pass)
      (kdf-pwhash-argon2 this config pass))
    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))
    ))

(define gcrypt-hkdf-impl%
  (class gcrypt-kdf-impl-base%
    (inherit about do-kdf)
    (init-field mac-algo)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) config config:info-kdf "HKDF"))
      ;; Note: requires non-empty pass
      (do-kdf GCRY_KDF_HKDF mac-algo
              #:length key-size
              #:params (list key-size)
              #:input pass
              #:salt #f
              #:key salt
              #:ad info))
    ))

;; GCRY_KDF_ONESTEP_KDF_MAC -- requires non-empty pass, info (ad)
;; GCRY_KDF_ONESTEP_KDF_MAC -- requires non-empty pass, key, info (ad)
;; GCRY_KDF_X963_KDF        -- requires non-empty pass
