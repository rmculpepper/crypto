;; Copyright 2012-2018 Ryan Culpepper
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
(require "../common/error.rkt")
(provide (all-defined-out))

;; References:
;; http://en.wikipedia.org/wiki/Padding_%28cryptography%29
;; http://msdn.microsoft.com/en-us/library/system.security.cryptography.paddingmode.aspx
;; http://tools.ietf.org/html/rfc5246#page-22
;; http://tools.ietf.org/html/rfc5652#section-6.3

;; pad-bytes/pkcs7 : Bytes Nat -> Bytes
;; PRE: 0 < block-size < 256
(define (pad-bytes/pkcs7 buf block-size)
  (define padlen
    ;; if buf already block-multiple, must add whole block of padding
    (let ([part (remainder (bytes-length buf) block-size)])
      (- block-size part)))
  (bytes-append buf (make-bytes padlen padlen)))

;; unpad-bytes/pkcs7 : Bytes -> Bytes
(define (unpad-bytes/pkcs7 buf)
  (define buflen (bytes-length buf))
  (when (zero? buflen) (crypto-error "bad PKCS7 padding"))
  (define pad-length (bytes-ref buf (sub1 buflen)))
  (define pad-start (- buflen pad-length))
  (unless (and (>= pad-start 0)
               (for/and ([i (in-range pad-start buflen)])
                 (= (bytes-ref buf i) pad-length)))
    (crypto-error "bad PKCS7 padding"))
  (subbytes buf 0 pad-start))

;; Other kinds of padding, for reference
;; - ansix923: zeros, then pad-length for final byte
;; - pkcs5: IIUC, same as pkcs7 except for 64-bit blocks only
;; - iso/iec-7816-4: one byte of #x80, then zeros
