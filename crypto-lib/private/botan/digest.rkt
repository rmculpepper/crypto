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
(provide botan2-digest-impl%)

(define botan2-digest-impl%
  (class digest-impl%
    (init-field master-ctx)
    (super-new)
    (inherit sanity-check get-size)

    (define/override (key-size-ok? size) #f)

    (define/override (-new-ctx key)
      (define ctx (botan_hash_copy_state master-ctx))
      (new botan2-digest-ctx% (impl this) (ctx ctx)))

    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    ))

(define botan2-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (botan_hash_update ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (botan_hash_final ctx buf))

    (define/override (-copy)
      (define ctx2 (botan_hash_copy_state ctx))
      (new botan2-digest-ctx% (impl impl) (ctx ctx2)))
    ))
