;; Copyright 2012-2013 Ryan Culpepper
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
         "../common/catalog.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-cipher-impl%)

(define gcrypt-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field cipher mode)
    (inherit-field spec)
    (inherit get-iv-size)
    (super-new)

    (define/override (get-default-key-size) (gcry_cipher_get_algo_keylen cipher))

    (define chunk-size (gcry_cipher_get_algo_blklen cipher))
    (define/override (get-chunk-size) chunk-size)

    (define/override (new-ctx key iv enc? pad?)
      (define iv-size (get-iv-size))
      (check-key-size spec (bytes-length key))
      (check-iv-size spec iv-size iv)
      (let ([ctx (gcry_cipher_open cipher mode 0)]
            [pad? (and pad? (cipher-spec-uses-padding? spec))])
        (gcry_cipher_setkey ctx key (bytes-length key))
        (when (positive? iv-size)
          (gcry_cipher_setiv ctx iv (bytes-length iv)))
        (when (or (= mode GCRY_CIPHER_MODE_CTR))
          (gcry_cipher_setctr ctx iv (bytes-length iv)))
        (new gcrypt-cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?) (pad? pad?))))
    ))

(define gcrypt-cipher-ctx%
  (class* whole-chunk-cipher-ctx% (cipher-ctx<%>)
    (inherit-field impl encrypt? pad?)
    (init-field ctx)
    (super-new)

    ;; FIXME: reconcile padding and stream ciphers (raise error?)

    (define/override (*crypt inbuf instart inend outbuf outstart outend)
      (let ([op (if encrypt? gcry_cipher_encrypt gcry_cipher_decrypt)])
        (op ctx
            (ptr-add outbuf outstart) (- outend outstart)
            (ptr-add inbuf instart) (- inend instart))))

    (define/override (*crypt-partial inbuf instart inend outbuf outstart outend)
      (case (cadr (send impl get-spec))
        [(ctr ofb cfb stream)
         (check-output-range outbuf outstart outend (- inend instart))
         (*crypt inbuf instart inend outbuf outstart outend)
         (- inend instart)]
        [else #f]))

    (define/override (*get-partial-output-size partlen)
      (case (cadr (send impl get-spec))
        [(ctr obf cfb stream) partlen]
        [else (super *get-partial-output-size partlen)]))

    (define/override (*open?)
      (and ctx #t))

    (define/override (*close)
      (when ctx
        (gcry_cipher_close ctx)
        (set! ctx #f)))
    ))
