;; Copyright 2012 Ryan Culpepper
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
(require racket/class
         racket/string
         "catalog.rkt"
         "interfaces.rkt")
(provide base-ctx%
         multikeylen-cipher-impl%
         shrink-bytes)

;; ----

(define base-ctx%
  (class* object% (ctx<%>)
    (init-field impl)
    (define/public (get-impl) impl)
    (super-new)))

(define multikeylen-cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field impls ;; (nonempty-listof (cons nat cipher-impl%))
                spec)
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-block-size) (send (car impls) get-block-size))
    (define/public (get-iv-size) (send (car impls) get-iv-size))

    (define/public (new-ctx who key iv enc? pad?)
      (cond [(assoc (bytes-length key) impls)
             => (lambda (keylen+impl)
                  (send (cdr keylen+impl) new-ctx who key iv enc? pad?))]
            [else
             (check-key-size who spec (bytes-length key))
             (error 'multikeylen-cipher-impl%
                    (string-append "internal error: no implementation for key length"
                                   "\n  cipher: ~e\n  given: ~s bytes\n  available: ~a")
                    spec (bytes-length key)
                    (string-join (map number->string (map car impls)) ", "))]))
    ))

;; ----

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
