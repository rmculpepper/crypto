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
         crypto/private/common/interfaces)
(provide semirandom-bytes
         semirandom-bytes/no-nul
         semirandom-bytes/alpha
         semirandom)

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

(define semirandom-impl%
  (class* object% (random-impl<%>)
    (super-new)
    (define/public (get-spec) #f)
    (define/public (get-factory) #f)
    (define/public (random-bytes! bs start end level)
      (for ([i (in-range start end)])
        (bytes-set! bs i (add1 (random 255)))))
    (define/public (ok?) #t)
    (define/public (can-add-entropy?) #f)
    (define/public (add-entropy . args) (void))
    ))

(define semirandom (new semirandom-impl%))
