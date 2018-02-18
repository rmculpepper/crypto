;; Copyright 2018 Ryan Culpepper
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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "digest.rkt")
(provide b2-factory)

(define blake2s-digests '(blake2s-256 blake2s-224 blake2s-160 blake2s-128))
(define blake2b-digests '(blake2b-512 blake2b-384 blake2b-256 blake2b-160))

(define b2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher)
    (super-new [ok? b2-ok?])

    (define/override (get-name) 'b2)

    (define/override (-get-digest info)
      (define spec (send info get-spec))
      (cond [(memq spec blake2b-digests)
             (new b2b-digest-impl% (info info) (factory this))]
            [(memq spec blake2s-digests)
             (new b2s-digest-impl% (info info) (factory this))]
            [else #f]))

    ;; ----

    (define/override (info key)
      (case key
        [(version) (and b2-ok? 'unknown)]
        [(all-digests) (append blake2b-digests blake2s-digests)]
        [(all-ciphers) null]
        [(all-pks) null]
        [(all-curves) null]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " Version: ~v\n" (info 'version))
      (printf "Available digests:\n")
      (for ([di (in-list (info 'all-digests))])
        (printf " ~v\n" di))
      (void))
    ))

(define b2-factory (new b2-factory%))
