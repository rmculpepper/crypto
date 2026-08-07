;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         #;"pkey.rkt"
         "kdf.rkt")
(provide sodium-factory)

(define (sodium-info key)
  (case key
    [(all-ec-curves) '()]
    [(all-eddsa-curves) '(ed25519)]
    [(all-ecx-curves) '(x25519)]
    [(sodium_version_string) (sodium_version_string)]
    [(sodium_library_version_major) (sodium_library_version_major)]
    [(sodium_library_version_minor) (sodium_library_version_minor)]
    [(extra-lib-info)
     `((sodium_version_string ,(sodium-info 'sodium_version_string))
       (sodium_library_version_major ,(sodium-info 'sodium_library_version_major))
       (sodium_library_version_minor ,(sodium-info 'sodium_library_version_minor)))]
    [else #f]))

(define sodium-factory
  (make-factory
   #:name 'sodium
   #:version (version->list (sodium_version_string))
   #:ok? (and sodium-ok? (sodium_init) #t)
   #:load-error sodium-load-error
   #:get-info sodium-info
   #:get-digest sodium-fetch-digest
   #:get-cipher sodium-fetch-cipher
   #:get-kdf sodium-fetch-kdf
   ;; #:get-pk sodium-fetch-pk
   ))
