;; Copyright 2012-2014 Ryan Culpepper
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
(require racket/class
         "../common/digest.rkt"
         "../common/common.rkt")
(provide pbkdf2*-hmac
         pbkdf2*)

;; References:
;; - http://tools.ietf.org/html/rfc2898
;; - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf

;; Performance tests: slower than libcrypto pbkdf2-hmac by about a factor of 2
;;  - tested up to 1e6 iterations w/ sha256: about 7 sec for 2 blocks of output
;;  - could be faster w/ reusable hmac ctxs?

(define (pbkdf2*-hmac dimpl pass salt iterations key-size)
  (define hlen (digest-size dimpl))
  (define PRF
    (cond [(send dimpl can-hmac-buffer!?)
           (lambda (key text textlen outbuf outstart)
             (send dimpl hmac-buffer! key text 0 textlen outbuf outstart))]
          [else ;; can reuse hmac-ctx?
           (define himpl (send dimpl get-hmac-impl))
           (define hctx (send himpl new-ctx pass))
           (lambda (key text textlen outbuf outstart)
             (send hctx update text 0 textlen)
             (send hctx final! outbuf outstart (bytes-length outbuf)))]))
  (pbkdf2* PRF hlen pass salt iterations key-size))

(define (pbkdf2* PRF hlen password salt iterations wantlen)
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
        (PRF password PRFin (if (= j 1) (+ saltlen 4) hlen) PRFout 0)
        (bytes-xor! resultbuf Fstart PRFout 0 hlen)
        ;; set up PRFin for next iter
        (bytes-copy! PRFin 0 PRFout 0 hlen)
        (Uloop (add1 j) hlen))))

  (for ([i (in-range 1 (add1 wantblocks))])
    (F i))

  (shrink-bytes resultbuf wantlen))

(define (bytes-xor! dest deststart src srcstart srcend)
  (for ([si (in-range srcstart srcend)]
        [di (in-naturals deststart)])
    (bytes-set! dest di (bitwise-xor (bytes-ref dest di) (bytes-ref src si)))))
