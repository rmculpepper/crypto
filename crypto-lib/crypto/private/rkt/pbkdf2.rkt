;; Copyright 2012 Ryan Culpepper
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

;; Reference: http://tools.ietf.org/html/rfc2898
;; and http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

(define (make-pbkdf2/hmac di)
  (define hlen (digest-size di))
  (define (PRF key text textlen outbuf outstart)
    ....)
  (lambda (password salt iterations wantlen)
    (pbkdf2* PRF hlen password salt iterations wantlen)))


(define (pbkdf2* prf hlen password salt iterations wantlen)
  ;; wantlen = desired length of key to generate
  (define wantblocks
    (let-values ([(q r) (quotient/remainder wantlen hlen)])
      (+ q (if (zero? r) 0 1))))
  (define passlen (bytes-length password))
  (define saltlen (bytes-length salt))

  (define resultbuf (make-bytes (* wantblocks hlen) 0))
  (define PRFin (make-bytes (max hlen (+ saltlen 4)))) ;; input to PRF
  (define PRFout (make-bytes hlen))

  (define (F i) ;; in RFC: F(P, S, c, i)
    ;; Note: i starts at 1
    ;; Store intermediate (XOR U_1 ...) in resultbuf starting at (* (sub1 i) hlen)
    (define Fstart (* (sub1 i) hlen))
    ;; set up PRFin *before* start of loop
    (bytes-copy! PRFin 0 salt 0)
    (integer->integer-bytes i 4 #f #t PRFin saltlen)
    (let Uloop ([j 1] [PRFinlen (+ passlen saltlen 4)])
      (unless (> j iterations)
        (PRF password PRFin PRFinlen PRFout)
        (bytes-xor! resultbuf Fstart PRFout 0 hlen)
        ;; set up PRFin for next iter
        (bytes-copy! PRFin passlen PRFout 0 hlen)
        (Uloop (add1 j) hlen))))

  (for ([i (in-range 1 (add1 wantblocks))])
    (F i))

  (shrink-bytes resultbuf wantlen))

(define (bytes-xor! dest deststart src srcstart srcend)
  (for ([si (in-range srcstart srcend)]
        [di (in-naturals deststart)])
    (bytes-set! di (bitwise-xor (bytes-ref dest di) (bytes-ref src si)))))
