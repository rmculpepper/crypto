;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide argon2-factory)

;; ----------------------------------------

(struct argon2-kdf-impl common-kdf-impl ()
  #:properties
  (method-properties
   #:export ([kdf-impl$ #:prefix %])
   #:import ([kdf-impl$ #:super #:prefix super-])
   (define-struct-abbrevs argon2-kdf-impl)

   (define (%pwhash self config pass)
     (define-values (t m p v)
       (check/ref-config '(t m p v) config config:argon2-base #:in self))
     (unless (eqv? v 19)
       (crypto-error "argon2 version unsupported\n  version: ~e" v #:in self))
     (define key-size 32)
     (define salt (crypto-random-bytes 16))
     (define cred
       (case ($get-spec self)
         [(argon2d)  (argon2d_hash_encoded  t m p pass salt key-size)]
         [(argon2i)  (argon2i_hash_encoded  t m p pass salt key-size)]
         [(argon2id) (argon2id_hash_encoded t m p pass salt key-size)]))
     (cond [(string? cred) cred]
           [else (crypto-error "failed")]))

   (define (%pwhash-verify self pass cred)
     (define spec ($get-spec self))
     (check-pwhash/kdf-spec cred spec)
     (case spec
       [(argon2d)  (argon2d_verify  cred pass)]
       [(argon2i)  (argon2i_verify  cred pass)]
       [(argon2id) (argon2id_verify cred pass)]))
   ))

(define (argon2-kdf-inner-impl)
  (common-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define-values (t m p v)
       (check/ref-config '(t m p v) config config:argon2-kdf #:in kdfi))
     (unless (eqv? v 19)
       (crypto-error "argon2 version unsupported\n  version: ~e" v #:in kdfi))
     (case ($get-spec kdfi)
       [(argon2d)  (argon2d_hash_raw  t m p pass salt key-size)]
       [(argon2i)  (argon2i_hash_raw  t m p pass salt key-size)]
       [(argon2id) (argon2id_hash_raw t m p pass salt key-size)]))))

;; ----------------------------------------

(define (argon2-fetch-kdf factory info)
  (define (make-argon2)
    (argon2-kdf-impl info factory (argon2-kdf-inner-impl)))
  (case ($get-spec info)
    [(argon2d) (make-argon2)]
    [(argon2i) (make-argon2)]
    [(argon2id) (make-argon2)]
    [else #f]))

;; ----------------------------------------

(define argon2-factory
  (make-factory
   #:name 'argon2
   #:version '()
   #:ok? argon2-ok?
   #:load-error argon2-load-error
   #:get-kdf argon2-fetch-kdf))
