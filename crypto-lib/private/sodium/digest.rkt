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
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "../rkt/hmac.rkt"
         "ffi.rkt")
(provide sodium-blake2-digest-impl%)

(define (make-ctx size) (malloc size 'atomic-interior))

(define sodium-blake2-digest-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)

    (define/override (key-size-ok? size)
      (<= (crypto_generichash_blake2b_keybytes_min)
          size
          (crypto_generichash_blake2b_keybytes_max)))

    (define/override (-new-ctx key)
      (define ctx (make-ctx (crypto_generichash_blake2b_statebytes)))
      (crypto_generichash_blake2b_init ctx (or key #"") (get-size))
      (new sodium-blake2b-digest-ctx% (impl this) (ctx ctx)))

    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    ))

(define sodium-blake2b-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (crypto_generichash_blake2b_update ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (crypto_generichash_blake2b_final ctx buf))

    (define/override (-copy)
      (define size (crypto_generichash_blake2b_statebytes))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (new sodium-blake2b-digest-ctx% (impl impl) (ctx ctx2)))
    ))
