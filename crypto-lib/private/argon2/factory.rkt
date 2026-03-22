;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "../common/kdf.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide argon2-factory)

;; ----------------------------------------

(define argon2-kdf-impl%
  (class kdf-impl-base%
    (inherit about)
    (inherit-field spec)
    (super-new)

    (define/override (-derive key-size config pass salt)
      (define-values (t m p v)
        (check/ref-config '(t m p v) config config:argon2-kdf "argon2"))
      (check-version v)
      (case spec
        [(argon2d)  (argon2d_hash_raw  t m p pass salt key-size)]
        [(argon2i)  (argon2i_hash_raw  t m p pass salt key-size)]
        [(argon2id) (argon2id_hash_raw t m p pass salt key-size)]))

    (define/override (pwhash config pass)
      (define-values (t m p v)
        (check/ref-config '(t m p v) config config:argon2-base "argon2"))
      (check-version v)
      (define key-size 32)
      (define salt (crypto-random-bytes 16))
      (define cred
        (case spec
          [(argon2d)  (argon2d_hash_encoded  t m p pass salt key-size)]
          [(argon2i)  (argon2i_hash_encoded  t m p pass salt key-size)]
          [(argon2id) (argon2id_hash_encoded t m p pass salt key-size)]))
      (cond [(string? cred) cred]
            [else (crypto-error "failed")]))

    (define/private (check-version v)
      (unless (eqv? v 19)
        (crypto-error "argon2 version unsupported\n  version: ~e\n  impl: ~a"
                      v (about))))

    (define/override (pwhash-verify pass cred)
      (check-pwhash/kdf-spec cred spec)
      (case spec
        [(argon2d)  (argon2d_verify  cred pass)]
        [(argon2i)  (argon2i_verify  cred pass)]
        [(argon2id) (argon2id_verify cred pass)]))
    ))

;; ----------------------------------------

(define argon2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-kdf)
    (super-new [ok? argon2-ok?] [load-error argon2-load-error])

    (define/override (get-name) 'argon2)
    (define/override (get-version) (and argon2-ok? '()))

    (define/override (-get-kdf spec)
      (case spec
        [(argon2d)  (new argon2-kdf-impl% (factory this) (spec 'argon2d))]
        [(argon2i)  (new argon2-kdf-impl% (factory this) (spec 'argon2i))]
        [(argon2id) (new argon2-kdf-impl% (factory this) (spec 'argon2id))]
        [else #f]))

    (define/override (info key)
      (case key
        [(all-kdfs) (filter (lambda (s) (get-kdf s)) '(argon2d argon2i argon2id))]
        [else (super info key)]))
    ))

(define argon2-factory (new argon2-factory%))
