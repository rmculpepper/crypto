;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "ffi.rkt")
(provide sodium-blake2-digest-impl%
         sodium-sha256-digest-impl%
         sodium-sha512-digest-impl%)

(define (make-ctx size) (malloc size 'atomic-interior))

(define sodium-blake2-digest-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)

    (define/override (key-size-ok? size)
      (<= (crypto_generichash_blake2b_keybytes_min)
          size
          (crypto_generichash_blake2b_keybytes_max)))

    (define/override (-new-ctx key)
      (define ctx (make-ctx (crypto_generichash_blake2b_statebytes)))
      (crypto_generichash_blake2b_init ctx (or key #"") (get-size))
      (new sodium-blake2b-digest-ctx% (impl this) (ctx ctx)))

    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    ))

(define sodium-blake2b-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (crypto_generichash_blake2b_update ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (crypto_generichash_blake2b_final ctx buf))

    (define/override (-copy)
      (define size (crypto_generichash_blake2b_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-blake2b-digest-ctx% (impl impl) (ctx ctx2)))
    ))

;; ----

(define sodium-sha256-digest-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)
    (define/override (-new-ctx key)
      (define ctx (make-ctx (crypto_hash_sha256_statebytes)))
      (crypto_hash_sha256_init ctx)
      (new sodium-sha256-digest-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (define ctx (make-ctx (crypto_auth_hmacsha256_statebytes)))
      (crypto_auth_hmacsha256_init ctx key (bytes-length key))
      (new sodium-hmac-sha256-digest-ctx% (impl this) (ctx ctx)))
    ))

(define sodium-sha256-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (crypto_hash_sha256_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (crypto_hash_sha256_final ctx buf))
    (define/override (-copy)
      (define size (crypto_hash_sha256_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-sha256-digest-ctx% (impl impl) (ctx ctx2)))
    ))

(define sodium-hmac-sha256-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (crypto_auth_hmacsha256_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (crypto_auth_hmacsha256_final ctx buf))
    (define/override (-copy)
      (define size (crypto_auth_hmacsha256_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-hmac-sha256-digest-ctx% (impl impl) (ctx ctx2)))
    ))

;; ----

(define sodium-sha512-digest-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)
    (define/override (-new-ctx key)
      (define ctx (make-ctx (crypto_hash_sha512_statebytes)))
      (crypto_hash_sha512_init ctx)
      (new sodium-sha512-digest-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (define ctx (make-ctx (crypto_auth_hmacsha512_statebytes)))
      (crypto_auth_hmacsha512_init ctx key (bytes-length key))
      (new sodium-hmac-sha512-digest-ctx% (impl this) (ctx ctx)))
    ))

(define sodium-sha512-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (crypto_hash_sha512_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (crypto_hash_sha512_final ctx buf))
    (define/override (-copy)
      (define size (crypto_hash_sha512_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-sha512-digest-ctx% (impl impl) (ctx ctx2)))
    ))

(define sodium-hmac-sha512-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (crypto_auth_hmacsha512_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (crypto_auth_hmacsha512_final ctx buf))
    (define/override (-copy)
      (define size (crypto_auth_hmacsha512_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-hmac-sha512-digest-ctx% (impl impl) (ctx ctx2)))
    ))
