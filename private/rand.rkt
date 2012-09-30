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

(define-crypto RAND_add
  (_fun (bs : _bytes)
        (len : _int = (bytes-length bs))
        (entropy : _int)
        -> _void))

(define-crypto RAND_seed
  (_fun (bs : _bytes)
        (len : _int = (bytes-length bs))
        -> _void))

(define-crypto RAND_status
  (_fun -> _bool))

(define-crypto RAND_load_file
  (_fun _path
        _long
        -> _int))

(define-crypto RAND_write_file
  (_fun _path
        -> _int))

(define-crypto RAND_file_name
  (_fun -> _path))

(define-rule (define-rand rand rand! randf)
  (begin
    (define* rand!
      ((bs) (randf bs (bytes-length bs)))
      ((bs start)
       (check-output-range rand! bs start (bytes-length bs))
       (randf (ptr-add bs start) (- (bytes-length bs) start)))
      ((bs start end)
       (check-output-range rand! bs start end)
       (randf (ptr-add bs start) (- end start))))
    (define (rand k)
      (let ((bs (make-bytes k)))
        (randf bs k)
        bs))
    (put-symbols! rand.symbols rand rand!)))

(define-symbols rand.symbols
  (RAND_status random-rnd-status)
  (RAND_add random-rnd-add)
  (RAND_seed random-rnd-seed)
  (RAND_load_file random-rnd-read)
  (RAND_write_file random-rnd-write)
  (RAND_file_name random-rnd-filename))

(define-rand random-bytes random-bytes! RAND_bytes)
(define-rand pseudo-random-bytes pseudo-random-bytes! RAND_pseudo_bytes)

(define-provider provide-rand rand.symbols)
