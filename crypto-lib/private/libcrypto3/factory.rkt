;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         #;"pkey.rkt"
         #;"kdf.rkt")
(provide libcrypto-factory)

(define libcrypto-digests
  #hasheq(;; DigestSpec => String
          [md4       . "md4"]
          [md5       . "md5"]
          [ripemd160 . "ripemd160"]
          [sha0      . "sha"]
          [sha1      . "sha1"]
          [sha224    . "sha224"]
          [sha256    . "sha256"]
          [sha384    . "sha384"]
          [sha512    . "sha512"]
          [sha512/224 . "sha512-224"]
          [sha512/256 . "sha512-256"]
          [sha3-224  . "sha3-224"]
          [sha3-256  . "sha3-256"]
          [sha3-384  . "sha3-384"]
          [sha3-512  . "sha3-512"]
          ))

(define libcrypto-ciphers
  '(;; [CipherName Modes KeySizes String]
    ;; Note: key sizes in bits (to match lookup string); converted to bytes below
    ;; keys=#f means inherit constraints, don't add to string
    [aes (cbc cfb #|cfb1 cfb8|# ctr ecb gcm ofb #|xts|#) (128 192 256) "aes"]
    [blowfish (cbc cfb ecb ofb) #f "bf"]
    [camellia (cbc cfb #|cfb1 cfb8|# ecb ofb) (128 192 256) "camellia"]
    [cast128 (cbc cfb ecb ofb) #f "cast5"]
    [des (cbc cfb #|cfb1 cfb8|# ecb ofb) #f "des"]
    [des-ede2 (cbc cfb ofb) #f "des-ede"] ;; ECB mode???
    [des-ede3 (cbc cfb ofb) #f "des-ede3"] ;; ECB mode???
    [rc4 (stream) #f "rc4"]
    [chacha20 (stream) #f "chacha20"] ;; libcrypto reports wrong IV length
    [chacha20-poly1305 (stream) #f "chacha20-poly1305"]))

;; ----------------------------------------

(define libcrypto3-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher get-pk get-kdf)
    (super-new [ok? libcrypto3-ok?]
               [load-error #f])

    (field [libctx (and libcrypto3-ok? (OSSL_LIB_CTX_new))])
    (when libctx
      (OSSL_PROVIDER_load libctx "default")
      (OSSL_PROVIDER_load libctx "legacy"))

    (define/public (get-libctx) libctx)

    (define/override (get-name) 'libcrypto)
    (define/override (get-version)
      (and libcrypto3-ok?
           (list (OPENSSL_version_major)
                 (OPENSSL_version_minor)
                 (OPENSSL_version_patch))))

    (define/override (-get-digest info)
      (define evp (-get-digest-evp (send info get-spec)))
      (and evp (new libcrypto3-digest-impl% (info info) (factory this) (md evp))))

    (define/public (-get-digest-evp spec)
      (define name-string (hash-ref libcrypto-digests spec #f))
      (and name-string (EVP_MD_fetch libctx name-string #f)))

    (define/override (-get-cipher info)
      (define evp/s (-get-cipher-evp (send info get-cipher-name) (send info get-mode)))
      (make-cipher info evp/s))

    (define/private (-get-cipher-evp cipher-name mode)
      (case mode
        [(stream)
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ '(stream) #f name-string)
            (EVP_CIPHER_fetch libctx name-string #f)]
           [_ #f])]
        [else
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ modes keys name-string)
            (and (memq mode modes)
                 (cond [keys
                        (for/list ([key (in-list keys)])
                          (define s (format "~a-~a-~a" name-string key mode))
                          (cons (quotient key 8) (EVP_CIPHER_fetch libctx s #f)))]
                       [else
                        (define s (format "~a-~a" name-string mode))
                        (EVP_CIPHER_fetch libctx s #f)]))]
           [_ #f])]))

    (define/private (make-cipher info evp/s)
      (cond [(list? evp/s)
             (for/list ([keylen+evp (in-list evp/s)] #:when (cdr keylen+evp))
               (cons (car keylen+evp) (make-cipher info (cdr keylen+evp))))]
            [evp/s
             (new libcrypto3-cipher-impl% (info info) (factory this) (cipher evp/s))]
            [else #f]))
    ))

(define libcrypto-factory (new libcrypto3-factory%))
