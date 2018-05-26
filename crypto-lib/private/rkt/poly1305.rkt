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
(require binaryio/integer)
(provide (all-defined-out))

;; Reference: https://tools.ietf.org/html/rfc7539

(define AUTHLEN 16)

;; poly1305 : Bytes[32] Bytes -> Bytes[16]
(define (poly1305 key msg)
  (define r (bytes->integer key #f #f 0 16))
  (define s (bytes->integer key #f #f 16 32))
  (integer->bytes (poly1305* r s msg) 16 #f #f))

;; poly1305*
;;   r   : Nat (128 bits)
;;   s   : Nat (128 bits)
;;   msg : Bytes
(define (poly1305* r0 s msg)
  (define P #x3fffffffffffffffffffffffffffffffb)
  (define r (clamp r0))
  (define acc
    (for/fold ([acc 0])
              ([i (in-range 0 (bytes-length msg) 16)])
      (define end (min (bytes-length msg) (+ i 16)))
      (define n0 (bytes->integer msg #f #f i (min (bytes-length msg) (+ i 16))))
      (define n1 (+ n0 (expt 2 (* 8 (- end i)))))
      (modulo (* r (+ acc n1)) P)))
  (bitwise-bit-field (+ acc s) 0 128))

(define (clamp r0)
  ;; mask =   #x 0f ff ff fc 0f ff ff fc 0f ff ff fc 0f ff ff ff
  ;;             15 14 13 12 11 10  9  8  7  6  5  4  3  2  1  0
  (define mask #x0ffffffc0ffffffc0ffffffc0fffffff)
  (bitwise-and r0 mask))

;; ----

(module+ test
  ;; (define key #x1bf54941aff6bf4afdb20dfb8a800301a806d542fe52447f336d555778bed685)
  (define s   #x1bf54941aff6bf4afdb20dfb8a800301)
  (define r   #x806d5400e52447c036d555408bed685)
  (define msg #"Cryptographic Forum Research Group")
  (equal? (poly1305* r s msg) #xa927010caf8b2bc2c6365130c11d06a8))
