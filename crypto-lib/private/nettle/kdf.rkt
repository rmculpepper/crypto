;; Copyright 2014-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/kdf.rkt"
         "ffi.rkt")
(provide nettle-fetch-kdf)

(define (nettle-fetch-kdf factory info)
  (define spec ($get-spec info))
  (define (make-pbkdf2 dspec)
    (make-kdf info factory (nettle-pbkdf2-inner-impl dspec)))
  (define inner
    (match spec
      ['(pbkdf2 hmac sha1)   (nettle-pbkdf2-inner-impl 'sha1)]
      ['(pbkdf2 hmac sha256) (nettle-pbkdf2-inner-impl 'sha256)]
      ['(pbkdf2 hmac sha384) (and nettle_pbkdf2_hmac_sha384
                                  (nettle-pbkdf2-inner-impl 'sha384))]
      ['(pbkdf2 hmac sha512) (and nettle_pbkdf2_hmac_sha512
                                  (nettle-pbkdf2-inner-impl 'sha512))]
      [_ #f]))
  (make-kdf info factory inner))

;; ----------------------------------------

;; Nettle's general pbkdf2 function needs hmac_<digest>_{update,digest} functions;
;; not feasible (or at least not easy).

(define (nettle-pbkdf2-inner-impl dspec)
  (common-kdf-inner-impl
   (lambda (kdfi key-size config pass salt)
     (define iters (check/ref-config '(iterations) config config:pbkdf2-kdf "PBKDF2"))
     (case dspec
       [(sha1)   (nettle_pbkdf2_hmac_sha1 pass salt iters key-size)]
       [(sha256) (nettle_pbkdf2_hmac_sha256 pass salt iters key-size)]
       [(sha384) (nettle_pbkdf2_hmac_sha384 pass salt iters key-size)]
       [(sha512) (nettle_pbkdf2_hmac_sha512 pass salt iters key-size)]))))
