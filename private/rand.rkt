;; mzcrypto: libcrypto bindings for PLT-scheme
;; random bytes
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
(require ffi/unsafe
         "libcrypto.rkt"
         "macros.rkt"
         "error.rkt")
(provide (all-defined-out))

(define-crypto RAND_bytes
  (_fun (buf : _pointer)
        (len : _uint)
        -> _int)
  #:wrap (err-wrap/check 'RAND_bytes))

(define-crypto RAND_pseudo_bytes
  (_fun (buf : _pointer)
        (len : _uint)
        -> _int)
  #:wrap (err-wrap/check 'RAND_pseudo_bytes))

(define (rand!* randf bs start end)
  (check-output-range who bs start end)
  (randf (ptr-add bs start) (- end start)))

(define (rand* rand! k)
  (let ([bs (make-bytes k)])
    (rand! bs)
    bs))

(define (random-bytes! bs [start 0] [end (bytes-length bs)])
  (rand!* RAND_bytes bs start end))
(define (pseudo-random-bytes! bs [start 0] [end (bytes-length bs)])
  (rand!* RAND_pseudo_bytes bs start end))
(define (random-bytes k)
  (rand* random-bytes! k))
(define (pseudo-random-bytes k)
  (rand* pseudo-random-bytes! k))

(define-symbols rand.symbols random-bytes pseudo-random-bytes)
(define-provider provide-rand rand.symbols)
