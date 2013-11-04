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
         "../common/catalog.rkt"
         "ffi.rkt")
(provide gcrypt-cipher-impl%)

(define gcrypt-cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field cipher
                mode    ;; one of 'ecb, 'cbc, 'stream (rest unsupported)
                spec)
    (super-new)

    (define key-size (gcry_cipher_get_algo_keylen cipher))
    (define block-size (gcry_cipher_get_algo_blklen cipher))
    (define iv-size (cipher-spec-iv-size spec))

    (define/public (get-spec) spec)
    (define/public (get-key-size) key-size)
    (define/public (get-block-size) block-size)
    (define/public (get-iv-size) iv-size)

    (define/public (new-ctx who key iv enc? pad?)
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
  (class* whole-block-cipher-ctx% (cipher-ctx<%>)
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
         (*crypt inbuf instart inend outbuf outstart outend)
         (- inend instart)]
        [else #f]))

    (define/override (*open?)
      (and ctx #t))

    (define/override (*close)
      (gcry_cipher_close ctx)
      (set! ctx #f))
    ))
