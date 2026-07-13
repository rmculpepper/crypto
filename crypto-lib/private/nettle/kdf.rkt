;; Copyright 2014-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         "../common/common.rkt"
         "../common/kdf.rkt"
         "ffi.rkt")
(provide nettle-pbkdf2-impl%)

;; Nettle's general pbkdf2 function needs hmac_<digest>_{update,digest} functions;
;; not feasible (or at least not easy).

(define nettle-pbkdf2-impl%
  (class kdf-impl-base%
    (init-field dspec)
    (super-new)

    (define/override (-derive key-size config pass salt)
      (define iters (check/ref-config '(iterations) config config:pbkdf2-kdf "PBKDF2"))
      (case dspec
        [(sha1)   (nettle_pbkdf2_hmac_sha1 pass salt iters key-size)]
        [(sha256) (nettle_pbkdf2_hmac_sha256 pass salt iters key-size)]
        [(sha384) (nettle_pbkdf2_hmac_sha384 pass salt iters key-size)]
        [(sha512) (nettle_pbkdf2_hmac_sha512 pass salt iters key-size)]))
    ))
