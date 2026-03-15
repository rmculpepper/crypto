;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require checkers
         crypto/private/common/cipher)

(test #:name "padding"
  (check (pad-bytes/pkcs7 (bytes 1 2 3) 4)
         #:is (bytes 1 2 3 1))
  (check (pad-bytes/pkcs7 (bytes 1 2 3 4) 4)
         #:is (bytes 1 2 3 4 4 4 4 4))
  (check (unpad-bytes/pkcs7 (bytes 1 2 3 1))
         #:is (bytes 1 2 3))
  (check (unpad-bytes/pkcs7 (bytes 1 2 3 4 4 4 4 4))
         #:is (bytes 1 2 3 4))
  (check (unpad-bytes/pkcs7 (bytes 4 4 4 4))
         #:is (bytes))
  (check (unpad-bytes/pkcs7 (bytes)) #:error #rx"bad PKCS7 padding")
  (check (unpad-bytes/pkcs7 (bytes 1 2 3 4)) #:error #rx"bad PKCS7 padding")
  (check (unpad-bytes/pkcs7 (bytes 1 2 3 5)) #:error #rx"bad PKCS7 padding")
  (check (unpad-bytes/pkcs7 (bytes 1 2 1 2)) #:error #rx"bad PKCS7 padding"))
