;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide sodium-fetch-cipher)

(define (sodium-fetch-cipher factory info)
  (define spec ($get-spec info))
  (for/first ([rec (in-list cipher-records)]
              #:when (equal? (aeadcipher-spec rec) spec))
    (define inner (sodium-cipher-inner-impl rec))
    (define keylen (aeadcipher-keysize rec))
    (make-multikeylen-cipher info factory (list (cons keylen inner)))))

;; ----------------------------------------

(define (sodium-cipher-inner-impl cipher)
  ;; for sodium, pad? is always #f, output length same as text length
  (define (encrypt _pad? key iv aad text auth-len)
    (define outbuf (make-bytes (bytes-length text)))
    (define authbuf (make-bytes auth-len))
    (define auth-len* ((aeadcipher-encrypt cipher) outbuf authbuf text aad iv key))
    (unless auth-len* (crypto-error "encryption failed"))
    (unless (= auth-len* auth-len)
      (crypto-error "wrong size for authentication tag"))
    (values outbuf (bytes-length outbuf) authbuf))
  (define (decrypt _pad? key iv aad text auth-tag)
    (define outbuf (make-bytes (bytes-length text)))
    (define s ((aeadcipher-decrypt cipher) outbuf text auth-tag aad iv key))
    (unless (zero? s) (crypto-error "authenticated decryption failed"))
    (values outbuf (bytes-length outbuf)))
  (oneshot-cipher-inner-impl encrypt decrypt))

#|
(sanity-check #:iv-size (aeadcipher-noncesize cipher))
(define/override (get-key-size) (aeadcipher-keysize cipher))
(define/override (get-key-sizes) (list (aeadcipher-keysize cipher)))
(define/override (get-iv-size) (aeadcipher-noncesize cipher))
(define/override (get-auth-size) (aeadcipher-authsize cipher))
(define/override (get-chunk-size) 1)
|#
