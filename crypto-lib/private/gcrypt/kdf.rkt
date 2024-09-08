;; Copyright 2014-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/common.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-pbkdf2-impl%
         gcrypt-scrypt-impl%)

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
