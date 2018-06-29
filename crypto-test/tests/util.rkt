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
(provide (all-defined-out))

;; let's not exhaust our entropy pool on testing
(define (semirandom-bytes len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (random 256)))
    bs))

(define (semirandom-bytes/no-nul len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (add1 (random 255))))
    bs))

(define (semirandom-bytes/alpha len)
  (let ([bs (make-bytes len)])
    (for ([i (in-range len)])
      (bytes-set! bs i (+ 65 (random 26))))
    bs))

;; Used to print testing headers
(define current-header-port (make-parameter (current-output-port)))

;; hprintf : Integer FormatString Any ... -> Void
(define (hprintf level fmt . args)
  (define prefix
    (cond [(zero? level) ">> "]
          [(positive? level) (make-string (+ 1 (* 2 level)) #\space)]
          [(negative? level) (string-append "-" (make-string (* -2 level) #\space))]))
  (write-string prefix (current-header-port))
  (apply fprintf (current-header-port) fmt args)
  (flush-output (current-header-port)))

;; hprintf examples:
;; ">> HEADER"
;; "   level 1"
;; "     level 2"
;; "       level3"
;; "-      level 3 negative"
;; "-    level 2 negative"
