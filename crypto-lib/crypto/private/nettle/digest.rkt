;; Copyright 2013 Ryan Culpepper
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
         "ffi.rkt")
(provide nettle-digest-impl%)

(define (make-ctx size)
  (let ([ctx (malloc size 'atomic-interior)])
    (cpointer-push-tag! ctx HASH_CTX-tag)
    ctx))

(define nettle-digest-impl%
  (class* object% (digest-impl<%>)
    (init-field nh spec)
    (define hmac-impl #f)
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-size) (nettle_hash-digest_size nh))
    (define/public (get-block-size) (nettle_hash-digest_size nh))

    (define/public (new-ctx)
      (let ([ctx (make-ctx (nettle_hash-context_size nh))])
        ((nettle_hash-init nh) ctx)
        (new nettle-digest-ctx% (impl this) (nh nh) (ctx ctx))))

    (define/public (get-hmac-impl who)
      (unless hmac-impl (set! hmac-impl (new nettle-hmac-impl% (digest this) (nh nh))))
      hmac-impl)

    ;; ----

    (define/public (can-digest-buffer!?) #f)
    (define/public (digest-buffer! who buf start end outbuf outstart)
      (error 'digest-buffer! "unimplemented"))

    (define/public (can-hmac-buffer!?) #f)
    (define/public (hmac-buffer! who key buf start end outbuf outstart)
      (error 'hmac-buffer! "unimplemented"))
    ))

(define nettle-digest-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx nh)
    (inherit-field impl)
    (super-new)

    (define/public (update who buf start end)
      ((nettle_hash-update nh) ctx (- end start) (ptr-add buf start)))

    (define/public (final! who buf start end)
      ((nettle_hash-digest nh) ctx (- end start) (ptr-add buf start))
      (set! ctx #f)
      (send impl get-size))

    (define/public (copy who)
      (let* ([size (nettle_hash-context_size nh)]
             [ctx2 (make-ctx size)])
        (memmove ctx2 ctx size)
        (new nettle-digest-ctx% (impl impl) (nh nh) (ctx ctx2))))
    ))

;; ============================================================

(define nettle-hmac-impl%
  (class* object% (hmac-impl<%>)
    (init-field digest nh)
    (super-new)
    (define/public (get-digest) digest)
    (define/public (new-ctx who key)
      (let* ([size (nettle_hash-context_size nh)]
             [outer (make-ctx size)]
             [inner (make-ctx size)]
             [ctx (make-ctx size)])
        (nettle_hmac_set_key outer inner ctx nh key)
        (new nettle-hmac-ctx% (impl digest) (nh nh) (outer outer) (inner inner) (ctx ctx))))
    ))

(define nettle-hmac-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field nh outer inner ctx)
    (inherit-field impl)
    (super-new)

    (define/public (update who buf start end)
      (unless ctx (error who "HMAC context is closed"))
      (check-input-range who buf start end)
      (nettle_hmac_update ctx nh (ptr-add buf start) (- end start)))

    (define/public (final! who buf start end)
      (unless ctx (error who "HMAC context is closed"))
      (let ([size (nettle_hash-digest_size nh)])
        (check-output-range who buf start end size)
        (nettle_hmac_digest outer inner ctx nh (ptr-add buf start) (- end start))
        (set! ctx #f)
        size))

    (define/public (copy)
      (let* ([size (nettle_hash-context_size nh)]
             [ctx2 (make-ctx size)])
        (memmove ctx2 ctx size)
        (new nettle-hmac-ctx% (impl impl) (nh nh) (outer outer) (inner inner) (ctx ctx2))))
    ))
