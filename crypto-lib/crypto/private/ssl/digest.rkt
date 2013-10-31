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
(require ffi/unsafe
         racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "macros.rkt"
         "util.rkt"
         (only-in racket/list last))
(provide (all-defined-out))

;; FIXME: potential races all over the place

;; ============================================================

(define digest-impl%
  (class* object% (digest-impl<%>)
    (init-field md    ;; EVP_MD
                spec) ;; DigestSpec (symbol)
    (define size (EVP_MD_size md))
    (define hmac-impl #f)
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-size) size)
    (define/public (get-block-size) (EVP_MD_block_size md))

    (define/public (new-ctx)
      (let ([ctx (EVP_MD_CTX_create)])
        (EVP_DigestInit_ex ctx md)
        (new digest-ctx% (impl this) (ctx ctx))))

    (define/public (get-hmac-impl who)
      (unless hmac-impl (set! hmac-impl (new hmac-impl% (digest this))))
      hmac-impl)

    ;; ----

    ;; FIXME: tried to use EVP_Digest but got segfault
    (define/public (can-digest-buffer!?) #f)
    (define/public (digest-buffer! who buf start end outbuf outstart) (void))

    (define/public (can-hmac-buffer!?) #t)
    (define/public (hmac-buffer! who key buf start end outbuf outstart)
      (check-input-range who buf start end)
      (check-output-range who outbuf outstart (+ outstart size))
      (HMAC md key (bytes-length key) (ptr-add buf start) (- end start)
            (ptr-add outbuf outstart))
      (void))
    ))

(define digest-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/public (update who buf start end)
      (unless ctx (error who "digest context is closed"))
      (check-input-range who buf start end)
      (EVP_DigestUpdate ctx (ptr-add buf start) (- end start)))

    (define/public (final! who buf start end)
      (unless ctx (error who "digest context is closed"))
      (let ([size (send impl get-size)])
        (check-output-range who buf start end size)
        (EVP_DigestFinal_ex ctx (ptr-add buf start))
        (EVP_MD_CTX_destroy ctx)
        (set! ctx #f)
        size))

    (define/public (copy who)
      (and ctx
           (let ([other (send impl new-ctx)])
             (EVP_MD_CTX_copy_ex (get-field ctx other) ctx)
             other)))
    ))

;; ============================================================

(define hmac-impl%
  (class* object% (hmac-impl<%>)
    (init-field digest)
    (super-new)
    (define/public (get-digest) digest)
    (define/public (new-ctx who key)
      (let ([ctx (HMAC_CTX_new)])
        (HMAC_Init_ex ctx key (bytes-length key) (get-field md digest))
        (new hmac-ctx% (impl digest) (ctx ctx))))
    ))

(define hmac-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/public (update who buf start end)
      (check-input-range who buf start end)
      (HMAC_Update ctx (ptr-add buf start) (- end start)))

    (define/public (final! who buf start end)
      (unless ctx (error who "HMAC context is closed"))
      (let ([size (send impl get-size)])
        (check-output-range who buf start end size)
        (HMAC_Final ctx (ptr-add buf start))
        (HMAC_CTX_free ctx)
        (set! ctx #f)
        size))

    (define/public (copy) #f) ;; FIXME (?)
    ))
