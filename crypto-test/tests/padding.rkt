;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require rackunit
         crypto/private/common/cipher)

(check-equal? (pad-bytes/pkcs7 (bytes 1 2 3) 4)
              (bytes 1 2 3 1))
(check-equal? (pad-bytes/pkcs7 (bytes 1 2 3 4) 4)
              (bytes 1 2 3 4 4 4 4 4))
(check-equal? (unpad-bytes/pkcs7 (bytes 1 2 3 1))
              (bytes 1 2 3))
(check-equal? (unpad-bytes/pkcs7 (bytes 1 2 3 4 4 4 4 4))
              (bytes 1 2 3 4))
(check-equal? (unpad-bytes/pkcs7 (bytes 4 4 4 4))
              (bytes))

(check-exn #rx"bad PKCS7 padding" (lambda () (unpad-bytes/pkcs7 (bytes))))
(check-exn #rx"bad PKCS7 padding" (lambda () (unpad-bytes/pkcs7 (bytes 1 2 3 4))))
(check-exn #rx"bad PKCS7 padding" (lambda () (unpad-bytes/pkcs7 (bytes 1 2 3 5))))
(check-exn #rx"bad PKCS7 padding" (lambda () (unpad-bytes/pkcs7 (bytes 1 2 1 2))))
