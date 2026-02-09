;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require ffi/unsafe
         racket/class
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "../common/util.rkt"
         "ffi.rkt")
(provide libcrypto3-cipher-impl%)

(define libcrypto3-cipher-impl%
  (class cipher-impl-base%
    (init-field cipher)
    (inherit-field info)
    (inherit get-mode get-spec sanity-check)
    (super-new)

    (cond [(equal? (get-spec) '(chacha20 stream))
           ;; libcrypto chacha20 takes combined (counter || nonce) as IV
           (sanity-check #:block-size (EVP_CIPHER_get_block_size cipher))]
          [else
           (sanity-check #:iv-size (EVP_CIPHER_get_iv_length cipher)
                         #:block-size (EVP_CIPHER_get_block_size cipher))])

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (define ctx (HANDLEp (EVP_CIPHER_CTX_new)))
      (HANDLEp (EVP_CipherInit_ex2 ctx cipher #f #f (if enc? 1 0) #f))
      ;; ----
      ;; Rather than mode/cipher case analysis, change if not default.
      (let ([keylen (bytes-length key)]
            [default-keylen (EVP_CIPHER_get_key_length cipher)])
        (unless (= keylen default-keylen)
          (HANDLEp (EVP_CIPHER_CTX_set_key_length ctx keylen))))
      ;; Docs currently (2026-02) say to use ctrls for GCM, OCB, and based on my
      ;; reading of 3.0.5 src, ctrl forwards to params but not vice versa.
      (let ()
        (define (set-iv-length)
          (define ivlen (if iv (bytes-length iv) 0))
          (HANDLEp (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_IVLEN ivlen #f)
                   "EVP_CTRL_AEAD_SET_IVLEN"))
        (define (set-auth-length)
          (HANDLEp (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_TAG auth-len #f)
                   "EVP_CTRL_AEAD_SET_TAG, length only"))
        (case (get-mode)
          [(gcm)
           ;; No need (and not able) to set auth length. Just truncate tag.
           (set-iv-length)]
          [(ocb)
           (set-iv-length)
           (set-auth-length)]
          [(stream)
           (define spec (get-spec))
           (cond [(equal? spec '(chacha20 stream))
                  ;; libcrypto expects 16-byte IV: counter || nonce
                  (set! iv (bytes-append (make-bytes (- 16 (bytes-length iv)) 0) iv))]
                 [(equal? spec '(chacha20-poly1305 stream))
                  (when (not enc?) (set-auth-length))])]
          [(ccm siv)
           (internal-error "unsupported")]
          [else (void)]))
      ;; ----
      (HANDLEp (EVP_CipherInit_ex2 ctx #f key iv -1 #f))
      (HANDLEp (EVP_CIPHER_CTX_set_padding ctx 0))
      (new libcrypto3-cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?)
           (pad? pad?) (auth-len auth-len) (attached-tag? attached-tag?)))
    ))

(define libcrypto3-cipher-ctx%
  (class cipher-ctx%
    (init-field ctx)
    (inherit-field impl)
    (inherit get-chunk-size)
    (super-new)

    (define/override (-do-aad inbuf instart inend)
      (HANDLEp (EVP_CipherUpdate ctx #f (ptr-add inbuf instart) (- inend instart))))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      (HANDLEp (EVP_CipherUpdate ctx outbuf (ptr-add inbuf instart) (- inend instart))))

    (define/override (-do-encrypt-end auth-len)
      (define outbuf (make-bytes (get-chunk-size)))
      (define outlen (or (NOERR (EVP_CipherFinal_ex ctx outbuf))
                         (err/crypt-failed #t (send impl aead?))))
      (unless (zero? outlen)
        (internal-error "unexpected output at end of encryption: ~e bytes" outlen))
      (define auth-tag (if (zero? auth-len) #"" (make-bytes auth-len)))
      (when (send impl aead?)
        (HANDLEp (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_GET_TAG auth-len auth-tag)
                 "EVP_CTRL_AEAD_GET_TAG"))
      (HANDLEp (EVP_CIPHER_CTX_reset ctx))
      auth-tag)

    (define/override (-do-decrypt-end auth-tag)
      (when auth-tag
        (define auth-len (bytes-length auth-tag))
        (HANDLEp (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_TAG auth-len auth-tag)))
      (define outbuf (make-bytes (get-chunk-size)))
      (define outlen (or (NOERR (EVP_CipherFinal_ex ctx outbuf))
                         (err/crypt-failed #f (send impl aead?))))
      (unless (zero? outlen)
        (internal-error "unexpected output at end of decryption: ~e bytes" outlen))
      (HANDLEp (EVP_CIPHER_CTX_reset ctx)))

    (define/override (-close)
      (when ctx (set! ctx #f)))
    ))
