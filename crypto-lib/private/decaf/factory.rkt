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
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "pkey.rkt")
(provide decaf-factory)

(define decaf-factory%
  (class* factory-base% (factory<%>)
    (inherit get-cipher get-kdf print-avail)
    (inherit-field ok?)
    (super-new [ok? (decaf-is-ok?)])

    (define/override (get-name) 'decaf)
    (define/override (get-version) (and ok? '()))

    (define/override (-get-digest info)
      (case (send info get-spec)
        [(sha512)
         (new decaf-sha512-impl% (info info) (factory this))]
        [else #f]))

    (define/override (-get-pk spec)
      (case spec
        [(eddsa) (new decaf-eddsa-impl% (factory this))]
        [(ecx) (new decaf-ecx-impl% (factory this))]
        [else #f]))

    (define/override (-get-pk-reader)
      (new decaf-read-key% (factory this)))

    ;; ----

    (define/override (info key)
      (case key
        [(all-ec-curves) '()]
        [(all-eddsa-curves) (if ok? '(ed25519 ed448) '())]
        [(all-ecx-curves) (if ok? '(x25519 x448) '())]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " version: ~v\n" (get-version))
      (print-avail))
    ))

(define decaf-factory (new decaf-factory%))
