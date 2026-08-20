;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt")
(provide gcrypt-factory)

(define (gcrypt-info key)
  (case key
    [(all-ec-curves) gcrypt-curves]
    [(all-eddsa-curves)
     (append (if ed25519-ok? '(ed25519) '()) (if ed448-ok? '(ed448) '()))]
    [(all-ecx-curves)
     (append (if x25519-ok? '(x25519) '()) (if x448-ok? '(x448) '()))]
    [(extra-lib-info)
     `(("version string" ,(gcry_check_version #f)))]
    [else #f]))

(define gcrypt-factory
  (make-factory
   #:name 'gcrypt
   #:version (version->list (gcry_check_version #f))
   #:ok? gcrypt-ok?
   #:load-error gcrypt-load-error

   #:get-digest gcrypt-fetch-digest
   #:get-cipher gcrypt-fetch-cipher
   #:get-kdf gcrypt-fetch-kdf
   #:get-pk gcrypt-fetch-pk

   #:get-info gcrypt-info))
