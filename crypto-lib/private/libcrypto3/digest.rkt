;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         ffi/unsafe
         "../common/digest.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide libcrypto3-digest-impl%)

(define libcrypto3-digest-impl%
  (class digest-impl%
    (init-field md [size #f] [mac #f])
    (super-new)
    (inherit about get-spec get-config-family sanity-check)
    (inherit-field factory)

    (define/override (get-size) (or size (super get-size)))

    (sanity-check #:size (or size (let ([size (EVP_MD_get_size md)])
                                    (and (> size 0) size)))
                  #:block-size (EVP_MD_get_block_size md))

    (define/override (-digest-buffer src start end osize)
      (cond [size #f]
            [else (let ([dbuf (make-bytes osize)])
                    (HANDLEp (EVP_Digest (ptr-add src start) (- end start) dbuf md))
                    dbuf)]))

    (define/override (-new-ctx2 key0 config)
      (define key (or key0 #""))
      (define key? (not (zero? (bytes-length key))))
      (define (config-params)
        (if (null? config) null (get-config-params key? config)))
      (cond [(and key? mac)
             (define ctx (HANDLEp (EVP_MAC_CTX_new mac)))
             (define params (make-param-array
                             `((#"size" uint ,size #:?)
                               ,@(config-params))))
             (HANDLEp (EVP_MAC_init ctx key params))
             (new libcrypto3-mac-ctx% (impl this) (ctx ctx))]
            [key?  ;; should be impossible
             (internal-error "key not supported (no MAC impl)" #:for this)]
            [else
             (define ctx (HANDLEp (EVP_MD_CTX_new)))
             (define params (make-param-array
                             `((#"size" uint ,size #:?)
                               ,@(config-params))))
             (HANDLEp (EVP_DigestInit_ex2 ctx md params))
             (new libcrypto3-digest-ctx% (impl this) (ctx ctx))]))

    (define/private (get-config-params key? config)
      (define config-family (get-config-family))
      (case config-family
        [(cshake)
         (define-values (function custom)
           (check/ref-config '(function custom) config config:cshake "cshake"))
         (check-bytes "custom" custom 0 512 #:for "cshake" #:in this)
         `((#"function-name" octet-string ,function #:?)
           (#"customization" octet-string ,custom #:?))]
        [(blake2b blake2s)
         (define-values (salt custom)
           (case config-family
             [(blake2b) (check/ref-config '(salt custom) config config:blake2b "blake2b")]
             [(blake2s) (check/ref-config '(salt custom) config config:blake2s "blake2s")]))
         (cond [key?
                `((#"salt"   octet-string ,salt #:?)
                  (#"custom" octet-string ,custom #:?))]
               [else
                ;; digest impl doesn't support salt, custom; MAC impl requires non-empty key
                (define (bad what)
                  (crypto-error "~a not supported with empty key" what #:in this))
                (unless (equal? salt #"") (bad "salt"))
                (unless (equal? custom #"") (bad "custom option"))
                '()])]
        [else
         (unless (null? config)
           (check-null-config config (get-spec) #:in this))
         null]))

    (define/override (-new-hmac-ctx key)
      (cond [size
             ;; No way to propagate nonstandard size to HMAC digest,
             ;; so fall back to Racket impl.
             (super -new-hmac-ctx key)]
            [else
             (define libctx (get-field libctx factory))
             (define hmac (HANDLEp (EVP_MAC_fetch libctx "HMAC" #f)))
             (define ctx (HANDLEp (EVP_MAC_CTX_new hmac)))
             (define digest-name (EVP_MD_get0_name md))
             (define params (make-param-array `((#"digest" utf8-string ,digest-name))))
             (HANDLEp (EVP_MAC_init ctx key params))
             (new libcrypto3-mac-ctx% (impl this) (ctx ctx))]))
    ))

(define libcrypto3-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (HANDLEp (EVP_DigestUpdate ctx (ptr-add buf start) (- end start))))

    (define/override (-final! buf)
      (HANDLEp (EVP_DigestFinal_ex ctx buf)))

    (define/override (-final-xof! buf)
      (HANDLEp (EVP_DigestFinalXOF ctx buf (bytes-length buf))))

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

    (define/override (-final-xof! buf)
      (HANDLEp (EVP_MAC_finalXOF ctx buf (bytes-length buf))))

    (define/override (-copy)
      (define ctx2 (HANDLEp (EVP_MAC_CTX_dup ctx)))
      (new libcrypto3-mac-ctx% (impl impl) (ctx ctx2)))
    ))
