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
         "../common/digest.rkt"
         "ffi.rkt")
(provide decaf-sha512-impl% decaf-sha3-impl%)

(define decaf-sha512-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size)
    (define/override (-new-ctx key)
      (define ctx (new-decaf_sha512_ctx))
      (decaf_sha512_init ctx)
      (new decaf-sha512-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    ))

(define decaf-sha512-ctx%
  (class digest-ctx%
    (inherit-field impl)
    (init-field ctx)
    (super-new)
    (define/override (-update buf start end)
      (decaf_sha512_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (decaf_sha512_final ctx buf (bytes-length buf)))
    (define/override (-copy)
      (define ctx2 (new-decaf_sha512_ctx))
      (memmove ctx2 ctx (ctype-sizeof _decaf_sha512_ctx_s))
      (new decaf-sha512-ctx% (impl impl) (ctx ctx2)))
    ))

;; ----------------------------------------

(define decaf-sha3-impl%
  (class digest-impl%
    (super-new)
    (inherit sanity-check get-size get-spec)
    (define/override (-new-ctx key)
      (define ctx (new-decaf_keccak_sponge))
      (decaf_sha3_init ctx (get-params))
      (new decaf-sha3-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))
    (define/override (-digest-buffer key buf start end)
      (define out (make-bytes (get-size)))
      (decaf_sha3_hash out (bytes-length out)
                       (ptr-add buf start) (- end start)
                       (get-params))
      out)
    (define/private (get-params)
      (case (get-spec)
        [(sha3-512) DECAF_SHA3_512]
        [(sha3-384) DECAF_SHA3_384]
        [(sha3-256) DECAF_SHA3_256]
        [(sha3-224) DECAF_SHA3_224]))
    ))

(define decaf-sha3-ctx%
  (class digest-ctx%
    (inherit-field impl)
    (init-field ctx)
    (super-new)
    (define/override (-update buf start end)
      (decaf_sha3_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (decaf_sha3_final ctx buf (bytes-length buf)))
    (define/override (-copy)
      (define ctx2 (new-decaf_keccak_sponge))
      (memmove ctx2 ctx (ctype-sizeof _decaf_keccak_sponge_s))
      (new decaf-sha3-ctx% (impl impl) (ctx ctx2)))
    ))
