;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "ffi.rkt")
(provide decaf-sha512-impl%)

(define decaf-sha512-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)
    (define/override (-new-ctx key)
      (define ctx (new-decaf_sha512_ctx))
      (decaf_sha512_init ctx)
      (new decaf-sha512-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    ))

(define decaf-sha512-ctx%
  (class digest-ctx%
    (inherit-field impl)
    (init-field ctx)
    (super-new)
    (define/override (-update buf start end)
      (decaf_sha512_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (decaf_sha512_final ctx buf (bytes-length buf)))
    (define/override (-copy)
      (define ctx2 (new-decaf_sha512_ctx))
      (memmove ctx2 ctx (ctype-sizeof _decaf_sha512_ctx_s))
      (new decaf-sha512-ctx% (impl impl) (ctx ctx2)))
    ))
