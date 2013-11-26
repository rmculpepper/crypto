;; Copyright 2012 Ryan Culpepper
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
(provide gcrypt-digest-impl%)

(define gcrypt-digest-impl%
  (class* impl-base% (digest-impl<%>)
    (init-field md         ;; int
                blocksize) ;; no way to fetch w/ ffi (?)
    (inherit-field spec)
    (super-new)

    (define hmac-impl #f)
    (define size (gcry_md_get_algo_dlen md))

    (define/public (get-size) size)
    (define/public (get-block-size) blocksize)

    (define/public (new-ctx)
      (let ([ctx (gcry_md_open md 0)])
        (new gcrypt-digest-ctx% (impl this) (ctx ctx))))

    (define/public (get-hmac-impl)
      (unless hmac-impl (set! hmac-impl (new gcrypt-hmac-impl% (digest this))))
      hmac-impl)

    ;; ----

    (define/public (can-digest-buffer!?) #t)
    (define/public (digest-buffer! buf start end outbuf outstart)
      (check-input-range buf start end)
      (check-output-range outbuf outstart (bytes-length outbuf) size)
      (gcry_md_hash_buffer md (ptr-add outbuf outstart)
                           (ptr-add buf start) (- end start)))

    (define/public (can-hmac-buffer!?) #f)
    (define/public (hmac-buffer! key buf start end outbuf outstart) (void))
    ))

(define gcrypt-digest-ctx%
  (class* ctx-base% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/public (update buf start end)
      (check-input-range buf start end)
      (gcry_md_write ctx (ptr-add buf start) (- end start)))

    (define/public (final! buf start end)
      (check-output-range buf start end (send impl get-size))
      (gcry_md_read ctx (ptr-add buf start) (- end start))
      (gcry_md_close ctx)
      (set! ctx #f)
      (send impl get-size))

    (define/public (copy)
      (let ([ctx2 (gcry_md_copy ctx)])
        (new gcrypt-digest-ctx% (impl impl) (ctx ctx2))))
    ))

;; ============================================================

(define gcrypt-hmac-impl%
  (class* object% (hmac-impl<%>)
    (init-field digest)
    (super-new)
    (define/public (get-spec) `(hmac ,(send digest get-spec)))
    (define/public (get-factory) (send digest get-factory))
    (define/public (get-digest) digest)
    (define/public (new-ctx key)
      (let ([ctx (gcry_md_open (get-field md digest) GCRY_MD_FLAG_HMAC)])
        (gcry_md_setkey ctx key (bytes-length key))
        (new gcrypt-digest-ctx% (impl digest) (ctx ctx))))
    ))
