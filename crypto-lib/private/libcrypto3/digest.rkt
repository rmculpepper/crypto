;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide libcrypto3-digest-impl%)

(define libcrypto3-digest-impl%
  (class digest-impl%
    (init-field md)
    (super-new)
    (inherit sanity-check)
    (inherit-field factory)

    (define/override (get-size) (EVP_MD_get_size md))
    (define/override (get-block-size) (EVP_MD_get_block_size md))

    (sanity-check #:size (get-size) #:block-size (get-block-size))

    (define/override (-digest-buffer src start end)
      (define dbuf (make-bytes (get-size)))
      (EVP_Digest (ptr-add src start) (- end start) dbuf md)
      dbuf)

    (define/override (-new-ctx key)
      (define ctx (HANDLEp (EVP_MD_CTX_new)))
      (HANDLEp (EVP_DigestInit_ex2 ctx md #f))
      (new libcrypto3-digest-ctx% (impl this) (ctx ctx)))

    (define/override (new-hmac-ctx key)
      (define libctx (get-field libctx factory))
      (define hmac (HANDLEp (EVP_MAC_fetch libctx "HMAC" #f)))
      (define ctx (HANDLEp (EVP_MAC_CTX_new hmac)))
      (define digest-name (EVP_MD_get0_name md))
      (define params (make-param-array `((#"digest" utf8-string ,digest-name))))
      (HANDLEp (EVP_MAC_init ctx key params))
      (new libcrypto3-mac-ctx% (impl this) (ctx ctx)))
    ))

(define libcrypto3-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (HANDLEp (EVP_DigestUpdate ctx (ptr-add buf start) (- end start))))

    (define/override (-final! buf)
      ;; FIXME: DigestFinalXOF when necessary
      (HANDLEp (EVP_DigestFinal_ex ctx buf))
      (void))

    (define/override (-copy)
      (define ctx2 (HANDLEp (EVP_MD_CTX_dup ctx)))
      (new libcrypto3-digest-ctx% (impl impl) (ctx ctx2)))
    ))

(define libcrypto3-mac-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (to-write-string prefix)
      (super to-write-string (or prefix "mac-ctx:")))

    (define/override (-update buf start end)
      (HANDLEp (EVP_MAC_update ctx (ptr-add buf start) (- end start))))

    (define/override (-final! buf)
      (HANDLEp (EVP_MAC_final ctx buf (bytes-length buf))))

    (define/override (-copy)
      (define ctx2 (HANDLEp (EVP_MAC_CTX_dup ctx)))
      (new libcrypto3-mac-ctx% (impl impl) (ctx ctx2)))
    ))
