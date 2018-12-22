;; Copyright 2012-2014 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
(require racket/contract/base)
(provide/contract
 [hex->bytes (-> (or/c bytes? string?) bytes?)]
 [bytes->hex (-> bytes? bytes?)]
 [bytes->hex-string (-> bytes? string?)]
 [crypto-bytes=? (-> bytes? bytes? boolean?)])

(define (byte->hex b) (bytes-ref #"0123456789abcdef" b))

(define (bytes->hex bs)
  (let* ([len (bytes-length bs)]
         [obs (make-bytes (* 2 len))])
    (for ([i (in-range len)])
      (let ([b (bytes-ref bs i)]
            [j (* 2 i)])
        (bytes-set! obs j (byte->hex (arithmetic-shift b -4)))
        (bytes-set! obs (add1 j) (byte->hex (bitwise-and b #x0f)))))
    obs))

(define (bytes->hex-string bs)
  (bytes->string/latin-1 (bytes->hex bs)))

(define (hex->bytes bs0)
  (define (bad)
    (error 'hex->bytes "expected even number of hexadecimal digits, got: ~e" bs0))
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
            [(<= ba c bf) (+ 10 (- c ba))]
            [else (bad)])))
  (let* ([bs (if (string? bs0) (string->bytes/latin-1 bs0) bs0)]
         [len (bytes-length bs)])
    (unless (even? len) (bad))
    (let* ([olen (quotient len 2)]
           [obs (make-bytes olen)])
      (for ([j (in-range olen)])
        (let ([i (* 2 j)])
          (bytes-set! obs j
                      (bitwise-ior
                       (arithmetic-shift (hex->byte (bytes-ref bs i)) 4)
                       (hex->byte (bytes-ref bs (add1 i)))))))
      obs)))

;; ============================================================
;; Comparison that does not leak information (through timing) about
;; the position of first different byte.

;; The following does, however, leak whether the lengths are equal.
(define (crypto-bytes=? a b)
  (and (= (bytes-length a) (bytes-length b))
       (for/fold ([same? #t]) ([ax (in-bytes a)] [bx (in-bytes b)])
         (and (= ax bx) same?))))
