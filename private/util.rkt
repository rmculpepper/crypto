;; mzcrypto: libcrypto bindings for PLT-scheme
;; byte utilities
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.
#lang racket/base
(require "macros.rkt")
(provide hex
         unhex
         shrink-bytes
         bytes-xor
         bytes-xor!)

(define (bytes-xor in key)
  (let* ((len (bytes-length in))
         (r (make-bytes len)))
    (do ((i 0 (1+ i)))
        ((= i len) r)
      (bytes-set! r i (bitwise-xor (bytes-ref in i) (bytes-ref key i))))))

(define (bytes-xor! in key)
  (let ((len (bytes-length in)))
    (do ((i 0 (1+ i)))
        ((= i len) in)
      (bytes-set! in i (bitwise-xor (bytes-ref in i) (bytes-ref key i))))))

(define hexes
  (list->vector (bytes->list #"0123456789abcdef")))

(define-rule (byte->hex b)
  (vector-ref hexes b))

(define (hex bs)
  (let* ((len (bytes-length bs))
         (obs (make-bytes (* 2 len))))
    (do ((i 0 (1+ i))
         (j 0 (+ 2 j)))
        ((= i len) obs)
      (let ((b (bytes-ref bs i)))
        (bytes-set! obs j (byte->hex (arithmetic-shift b -4)))
        (bytes-set! obs (1+ j) (byte->hex (bitwise-and b #x0f)))))))

(define digits
  (make-immutable-hasheq
   (append
    (for/list ((b #"0123456789") (n (in-range 10))) (cons b n))
    (for/list ((b #"abcdef") (n (in-range 10 16))) (cons b n))
    (for/list ((b #"ABCDEF") (n (in-range 10 16))) (cons b n)))))

(define-rule (hex->byte c)
  (hash-ref digits c))

(define (unhex bs)
  (let ((len (bytes-length bs)))
    (unless (even? len)
      (error 'unhex "odd length byte string"))
    (let ((obs (make-bytes (/ len 2))))
      (do ((i 0 (+ 2 i))
           (j 0 (1+ j)))
          ((= i len) obs)
        (bytes-set! obs j 
          (bitwise-ior (arithmetic-shift (hex->byte (bytes-ref bs i)) 4)
                       (hex->byte (bytes-ref bs (1+ i)))))))))

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
