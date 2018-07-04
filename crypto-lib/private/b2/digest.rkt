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
         "../common/digest.rkt"
         "../common/error.rkt"
         "../rkt/hmac.rkt"
         "ffi.rkt")
(provide b2s-digest-impl%
         b2b-digest-impl%)

(define b2s-digest-impl%
  (class digest-impl%
    (inherit get-size)
    (super-new)
    (define/override (-digest-buffer inbuf instart inend)
      (define outbuf (make-bytes (get-size)))
      (blake2s outbuf (ptr-add inbuf instart) (- inend instart) #f 0)
      outbuf)
    (define/override (-new-ctx key)
      (define ctx (new-blake2s-state))
      (if key
          (blake2s_init_key ctx (get-size) key)
          (blake2s_init ctx (get-size)))
      (new b2s-digest-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))))

(define b2b-digest-impl%
  (class digest-impl%
    (inherit get-size)
    (super-new)
    (define/override (-digest-buffer inbuf instart inend)
      (define outbuf (make-bytes (get-size)))
      (blake2b outbuf (ptr-add inbuf instart) (- inend instart) #f 0)
      outbuf)
    (define/override (-new-ctx key)
      (define ctx (new-blake2b-state))
      (if key
          (blake2b_init_key ctx (get-size) key)
          (blake2b_init ctx (get-size)))
      (new b2b-digest-ctx% (impl this) (ctx ctx)))
    (define/override (new-hmac-ctx key)
      (new rkt-hmac-ctx% (impl this) (key key)))))

;; ----

(define b2s-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (blake2s_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (blake2s_final ctx buf))
    (define/override (-copy)
      (define ctx2 (new-blake2s-state))
      (memmove ctx2 ctx blake2s-state-size)
      (new b2s-digest-ctx% (impl impl) (ctx ctx2)))
    ))

(define b2b-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)
    (define/override (-update buf start end)
      (blake2b_update ctx (ptr-add buf start) (- end start)))
    (define/override (-final! buf)
      (blake2b_final ctx buf))
    (define/override (-copy)
      (define ctx2 (new-blake2b-state))
      (memmove ctx2 ctx blake2b-state-size)
      (new b2b-digest-ctx% (impl impl) (ctx ctx2)))
    ))
