;; Copyright 2013-2018 Ryan Culpepper
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
(provide nettle-digest-impl%)

(define (make-ctx size)
  (let ([ctx (malloc size 'atomic-interior)])
    (cpointer-push-tag! ctx HASH_CTX-tag)
    ctx))

(define nettle-digest-impl%
  (class digest-impl%
    (init-field nh)
    (super-new)
    (inherit sanity-check)

    (define/override (get-size) (nettle_hash-digest_size nh))
    (define/override (get-block-size) (nettle_hash-block_size nh))

    (sanity-check #:size (get-size) #:block-size (get-block-size))

    (define/override (-new-ctx key)
      (let ([ctx (make-ctx (nettle_hash-context_size nh))])
        ((nettle_hash-init nh) ctx)
        (new nettle-digest-ctx% (impl this) (nh nh) (ctx ctx))))

    (define/override (new-hmac-ctx key)
      (let* ([size (nettle_hash-context_size nh)]
             [outer (make-ctx size)]
             [inner (make-ctx size)]
             [ctx (make-ctx size)])
        (nettle_hmac_set_key outer inner ctx nh key)
        (new nettle-hmac-ctx% (impl this) (nh nh) (outer outer) (inner inner) (ctx ctx))))
    ))

(define nettle-digest-ctx%
  (class digest-ctx%
    (init-field ctx nh)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      ((nettle_hash-update nh) ctx (- end start) (ptr-add buf start)))

    (define/override (-final! buf)
      ((nettle_hash-digest nh) ctx (bytes-length buf) buf)
      ((nettle_hash-init nh) ctx))

    (define/override (-copy)
      (let* ([size (nettle_hash-context_size nh)]
             [ctx2 (make-ctx size)])
        (memmove ctx2 ctx size)
        (new nettle-digest-ctx% (impl impl) (nh nh) (ctx ctx2))))
    ))

(define nettle-hmac-ctx%
  (class digest-ctx%
    (init-field nh outer inner ctx)
    (inherit-field impl)
    (super-new)

    (define/override (to-write-string prefix)
      (super to-write-string (or prefix "hmac-ctx:")))

    (define/override (-update buf start end)
      (nettle_hmac_update ctx nh (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (nettle_hmac_digest outer inner ctx nh buf (bytes-length buf)))

    (define/override (-copy)
      (let* ([size (nettle_hash-context_size nh)]
             [ctx2 (make-ctx size)])
        (memmove ctx2 ctx size)
        (new nettle-hmac-ctx% (impl impl) (nh nh) (outer outer) (inner inner) (ctx ctx2))))
    ))
