;; Copyright 2013-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         "kdf.rkt"
         "pkey.rkt")
(provide nettle-factory)

(define (nettle-info key)
  (case key
    [(all-ec-curves)
     (map car nettle-curves)]
    [(all-eddsa-curves)
     (append (if ed25519-ok? '(ed25519) '())
             (if ed448-ok? '(ed448) '()))]
    [(all-ecx-curves)
     (append (if x25519-ok? '(x25519) '())
             (if x448-ok? '(x448) '()))]
    [else #f]))

(define nettle-factory
  (make-factory
   #:name 'nettle
   #:version (list (nettle_version_major) (nettle_version_minor))
   #:ok? nettle-ok?
   #:load-error (or nettle-load-error hogweed-load-error)

   #:get-digest nettle-fetch-digest
   #:get-cipher nettle-fetch-cipher
   #:get-kdf nettle-fetch-kdf
   #:get-pk nettle-fetch-pk

   #:get-info nettle-info))
