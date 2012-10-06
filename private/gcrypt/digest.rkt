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
         "ffi.rkt")
(provide digest-impl%)

(define digest-impl%
  (class* object% (digest-impl<%>)
    (init-field md        ;; int
                blocksize ;; no way to fetch w/ ffi (?)
                name)     ;; symbol
    (define hmac-impl #f)
    (define size (gcry_md_get_algo_dlen md))
    (super-new)

    (define/public (get-name) name)
    (define/public (get-size) size)
    (define/public (get-block-size) blocksize)

    (define/public (new-ctx)
      (let ([ctx (gcry_md_open md 0)])
        (new digest-ctx% (impl this) (ctx ctx))))

    (define/public (get-hmac-impl who)
      (unless hmac-impl (set! hmac-impl (new hmac-impl% (digest this))))
      hmac-impl)

    (define/public (generate-hmac-key)
      ;; FIXME
      (let ([buf (make-bytes size)])
        (gcry_randomize buf size GCRY_STRONG_RANDOM)
        buf))

    ;; ----

    (define/public (can-digest-buffer!?) #t)
    (define/public (digest-buffer! who buf start end outbuf outstart)
      (gcry_md_hash_buffer md (ptr-add outbuf outstart)
                           (ptr-add buf start) (- end start)))

    (define/public (can-hmac-buffer!?) #f)
    (define/public (hmac-buffer! who key buf start end outbuf outstart) (void))
    ))

(define digest-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/public (update! who buf start end)
      (gcry_md_write ctx (ptr-add buf start) (- end start)))

    (define/public (final! who buf start end)
      (gcry_md_read ctx (ptr-add buf start) (- end start))
      (send impl get-size))

    (define/public (copy who)
      (let ([ctx2 (gcry_md_copy ctx)])
        (new digest-ctx% (impl impl) (ctx ctx2))))
    ))

;; ============================================================

(define hmac-impl%
  (class* object% (hmac-impl<%>)
    (init-field digest)
    (super-new)
    (define/public (get-digest) digest)
    (define/public (new-ctx who key)
      (let ([ctx (gcry_md_open (get-field md digest) GCRY_MD_FLAG_HMAC)])
        (gcry_md_setkey ctx key (bytes-length key))
        (new digest-ctx% (impl digest) (ctx ctx))))
    ))
