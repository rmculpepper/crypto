;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-cipher-impl%)

(define gcrypt-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field cipher mode)
    (inherit-field info)
    (inherit get-spec get-iv-size)
    (super-new)

    (define/override (get-key-size) (gcry_cipher_get_algo_keylen cipher))

    (define chunk-size (gcry_cipher_get_algo_blklen cipher))
    (define/override (get-chunk-size) chunk-size)

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (define iv-size (get-iv-size))
      (let ([ctx (gcry_cipher_open cipher mode 0)])
        (gcry_cipher_setkey ctx key (bytes-length key))
        (when (positive? iv-size)
          (gcry_cipher_setiv ctx iv (bytes-length iv)))
        (when (or (= mode GCRY_CIPHER_MODE_CTR))
          (gcry_cipher_setctr ctx iv (bytes-length iv)))
        (new gcrypt-cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?) (pad? pad?)
             (auth-len auth-len) (attached-tag? attached-tag?))))
    ))

(define gcrypt-cipher-ctx%
  (class cipher-ctx%
    (init-field ctx)
    (super-new)
    (inherit-field impl encrypt?)
    (inherit get-block-size)

    (define/public (get-spec) (send impl get-spec))

    (define/override (-close)
      (when ctx
        (gcry_cipher_close ctx)
        (set! ctx #f)))

    (define/override (-do-aad inbuf instart inend)
      (gcry_cipher_authenticate ctx (ptr-add inbuf instart) (- inend instart)))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      (when final? (gcry_cipher_final ctx))
      (define outlen (bytes-length outbuf))
      (if encrypt?
          (gcry_cipher_encrypt ctx outbuf outlen (ptr-add inbuf instart) (- inend instart))
          (gcry_cipher_decrypt ctx outbuf outlen (ptr-add inbuf instart) (- inend instart)))
      (- inend instart))

    (define/override (-do-encrypt-end auth-len)
      (cond [(positive? auth-len)
             (define tag (make-bytes auth-len))
             (gcry_cipher_gettag ctx tag auth-len)
             tag]
            [else #""]))

    (define/override (-do-decrypt-end auth-tag)
      (when (send impl aead?)
        (unless (= (gcry_cipher_checktag ctx auth-tag (bytes-length auth-tag)) GPG_ERR_NO_ERROR)
          (err/auth-decrypt-failed))))
    ))
