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
(provide hex
         unhex
         shrink-bytes
         bytes-xor
         bytes-xor!)

(define (bytes-xor in key)
  (let* ([len (bytes-length in)]
         [r (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! r i (bitwise-xor (bytes-ref in i) (bytes-ref key i))))
    r))

(define (bytes-xor! in key)
  (let ([len (bytes-length in)])
    (for ([i (in-range len)])
      (bytes-set! in i (bitwise-xor (bytes-ref in i) (bytes-ref key i)))))
  in)

(define (byte->hex b) (bytes-ref #"0123456789abcdef" b))

(define (hex bs)
  (let* ([len (bytes-length bs)]
         [obs (make-bytes (* 2 len))])
    (for ([i (in-range len)])
      (let ([b (bytes-ref bs i)]
            [j (* 2 i)])
        (bytes-set! obs j (byte->hex (arithmetic-shift b -4)))
        (bytes-set! obs (add1 j) (byte->hex (bitwise-and b #x0f)))))
    obs))

(define (hex->byte c)
  ;; (#\0 = 48) < (#\A = 65) < (#\a = 97)
  (let ([b0 (char->integer #\0)]
        [b9 (char->integer #\9)]
        [bA (char->integer #\A)]
        [bF (char->integer #\F)]
        [ba (char->integer #\a)]
        [bf (char->integer #\f)])
    (cond [(<= b0 c b9) (- c b0)]
          [(<= bA c bF) (+ 10 (- c bA))]
          [(<= ba c bf) (+ 10 (- c ba))])))

(define (unhex bs)
  (let ((len (bytes-length bs)))
    (unless (even? len)
      (error 'unhex "odd length byte string"))
    (let* ([olen (quotient len 2)]
           [obs (make-bytes olen)])
      (for ([j (in-range olen)])
        (let ([i (* 2 j)])
          (bytes-set! obs j
                      (bitwise-ior
                       (arithmetic-shift (hex->byte (bytes-ref bs i)) 4)
                       (hex->byte (bytes-ref bs (add1 i)))))))
      obs)))

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
