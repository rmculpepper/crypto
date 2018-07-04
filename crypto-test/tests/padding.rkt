;; Copyright 2018 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

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
