;; Copyright 2012-2018 Ryan Culpepper
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
(provide gcrypt-digest-impl%)

(define gcrypt-digest-impl%
  (class digest-impl%
    (init-field md) ;; int
    (init blocksize)
    (super-new)
    (inherit get-size sanity-check)

    (sanity-check #:size (gcry_md_get_algo_dlen md) #:block-size blocksize)

    (define/override (-new-ctx key)
      (let ([ctx (gcry_md_open md 0)])
        (when key (gcry_md_setkey ctx key (bytes-length key)))
        (new gcrypt-digest-ctx% (impl this) (ctx ctx))))

    (define/override (new-hmac-ctx key)
      (let ([ctx (gcry_md_open md GCRY_MD_FLAG_HMAC)])
        (gcry_md_setkey ctx key (bytes-length key))
        (new gcrypt-digest-ctx% (impl this) (ctx ctx))))

    (define/override (-digest-buffer key buf start end)
      (if key #f (-digest-buffer1 buf start end)))

    (define/private (-digest-buffer1 buf start end)
      ;; FIXME: docs say "will abort the process if an unavailable algorithm is used"
      ;; so maybe not worth the trouble?
      (define outbuf (make-bytes (get-size)))
      (gcry_md_hash_buffer md outbuf (ptr-add buf start) (- end start))
      outbuf)
    ))

(define gcrypt-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (gcry_md_write ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (gcry_md_read ctx buf (bytes-length buf))
      (gcry_md_close ctx))

    (define/override (-copy)
      (let ([ctx2 (gcry_md_copy ctx)])
        (new gcrypt-digest-ctx% (impl impl) (ctx ctx2))))
    ))
