;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/digest.rkt"
         "../common/cipher.rkt"
         "../common/kdf.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt")
(provide gcrypt-factory)

;; ----------------------------------------

(define digests
  `(;;[Name     AlgId               BlockSize  HMAC-AlgId]
    (sha1       ,GCRY_MD_SHA1       64    ,GCRY_MAC_HMAC_SHA1)
    (md2        ,GCRY_MD_MD2        16    ,GCRY_MAC_HMAC_MD2)
    (md5        ,GCRY_MD_MD5        64    ,GCRY_MAC_HMAC_MD5)
    (sha224     ,GCRY_MD_SHA224     64    ,GCRY_MAC_HMAC_SHA224)
    (sha256     ,GCRY_MD_SHA256     64    ,GCRY_MAC_HMAC_SHA256)
    (sha384     ,GCRY_MD_SHA384     128   ,GCRY_MAC_HMAC_SHA384)
    (sha512     ,GCRY_MD_SHA512     128   ,GCRY_MAC_HMAC_SHA512)
    (sha512/256 ,GCRY_MD_SHA512_256 128   ,GCRY_MAC_HMAC_SHA512_256)
    (sha512/224 ,GCRY_MD_SHA512_224 128   ,GCRY_MAC_HMAC_SHA512_224)
    (md4        ,GCRY_MD_MD4        64    ,GCRY_MAC_HMAC_MD4)
    (whirlpool  ,GCRY_MD_WHIRLPOOL  64    ,GCRY_MAC_HMAC_WHIRLPOOL)
    (sha3-224   ,GCRY_MD_SHA3_224   144   ,GCRY_MAC_HMAC_SHA3_224)
    (sha3-256   ,GCRY_MD_SHA3_256   136   ,GCRY_MAC_HMAC_SHA3_256)
    (sha3-384   ,GCRY_MD_SHA3_384   104   ,GCRY_MAC_HMAC_SHA3_384)
    (sha3-512   ,GCRY_MD_SHA3_512   72    ,GCRY_MAC_HMAC_SHA3_512)
    (shake128   ,GCRY_MD_SHAKE128   168   #f)
    (shake256   ,GCRY_MD_SHAKE256   136   #f)
    (cshake128  ,GCRY_MD_CSHAKE128  168   #f)
    (cshake256  ,GCRY_MD_CSHAKE256  136   #f)
    (blake2b-512 ,GCRY_MD_BLAKE2B_512 128 ,GCRY_MAC_HMAC_BLAKE2B_512)
    (blake2b-384 ,GCRY_MD_BLAKE2B_384 128 ,GCRY_MAC_HMAC_BLAKE2B_384)
    (blake2b-256 ,GCRY_MD_BLAKE2B_256 128 ,GCRY_MAC_HMAC_BLAKE2B_256)
    (blake2b-160 ,GCRY_MD_BLAKE2B_160 128 ,GCRY_MAC_HMAC_BLAKE2B_160)
    (blake2s-256 ,GCRY_MD_BLAKE2S_256 64  ,GCRY_MAC_HMAC_BLAKE2S_256)
    (blake2s-224 ,GCRY_MD_BLAKE2S_224 64  ,GCRY_MAC_HMAC_BLAKE2S_224)
    (blake2s-160 ,GCRY_MD_BLAKE2S_160 64  ,GCRY_MAC_HMAC_BLAKE2S_160)
    (blake2s-128 ,GCRY_MD_BLAKE2S_128 64  ,GCRY_MAC_HMAC_BLAKE2S_128)
    #|
    (ripemd160  ,GCRY_MD_RMD160     64) ;; Doesn't seem to be available!
    (haval      ,GCRY_MD_HAVAL      128)
    (tiger      ,GCRY_MD_TIGER      #f) ;; special old GnuPG-compat output order
    (tiger1     ,GCRY_MD_TIGER1     64)
    (tiger2     ,GCRY_MD_TIGER2     64)
    |#))

(define (get-digest-algid spec)
  (match (assq spec digests)
    [(list _ algid _ _)
     (and (gcry_md_test_algo algid) algid)]
    [_ #f]))

;; ----------------------------------------

(define block-ciphers
  `(;;[Name   ([KeySize AlgId] ...)]
    [cast128  ([128 ,GCRY_CIPHER_CAST5])]
    [blowfish ([128 ,GCRY_CIPHER_BLOWFISH])]
    [aes      ([128 ,GCRY_CIPHER_AES]
               [192 ,GCRY_CIPHER_AES192]
               [256 ,GCRY_CIPHER_AES256])]
    [twofish  ([128 ,GCRY_CIPHER_TWOFISH128]
               [256 ,GCRY_CIPHER_TWOFISH])]
    [serpent  ([128 ,GCRY_CIPHER_SERPENT128]
               [192 ,GCRY_CIPHER_SERPENT192]
               [256 ,GCRY_CIPHER_SERPENT256])]
    [camellia ([128 ,GCRY_CIPHER_CAMELLIA128]
               [192 ,GCRY_CIPHER_CAMELLIA192]
               [256 ,GCRY_CIPHER_CAMELLIA256])]
    [aria     ([128 ,GCRY_CIPHER_ARIA128]
               [192 ,GCRY_CIPHER_ARIA192]
               [256 ,GCRY_CIPHER_ARIA256])]
    [des      ([64  ,GCRY_CIPHER_DES])] ;; takes key as 64 bits, high bits ignored
    [des-ede3 ([192 ,GCRY_CIPHER_3DES])] ;; takes key as 192 bits, high bits ignored
    [idea     ([128 ,GCRY_CIPHER_IDEA])]
    ))

(define stream-ciphers
  `(;;[Name ([KeySize AlgId] ...) Mode]
    [rc4        ,GCRY_CIPHER_ARCFOUR            ,GCRY_CIPHER_MODE_STREAM]
    [salsa20    ([256 ,GCRY_CIPHER_SALSA20])    ,GCRY_CIPHER_MODE_STREAM]
    [salsa20r12 ([256 ,GCRY_CIPHER_SALSA20R12]) ,GCRY_CIPHER_MODE_STREAM]
    [chacha20   ([256 ,GCRY_CIPHER_CHACHA20])   ,GCRY_CIPHER_MODE_STREAM]
    [chacha20-poly1305 ([256 ,GCRY_CIPHER_CHACHA20]) ,GCRY_CIPHER_MODE_POLY1305]))

(define block-modes
  `(;;[Mode ModeId]
    [ecb    ,GCRY_CIPHER_MODE_ECB]
    [cbc    ,GCRY_CIPHER_MODE_CBC]
    [cfb    ,GCRY_CIPHER_MODE_CFB]
    [ofb    ,GCRY_CIPHER_MODE_OFB]
    [ctr    ,GCRY_CIPHER_MODE_CTR]
    ;; [ccm ,GCRY_CIPHER_MODE_CCM]
    [gcm    ,GCRY_CIPHER_MODE_GCM]
    [ocb    ,GCRY_CIPHER_MODE_OCB]
    ;; [xts ,GCRY_CIPHER_MODE_XTS]
    [eax    ,GCRY_CIPHER_MODE_EAX]
    ;; [siv    ,GCRY_CIPHER_MODE_SIV]
    ;; [gcm-siv ,GCRY_CIPHER_MODE_GCM_SIV]
    ))

;; GCrypt does not seem to have a function to test whether a cipher
;; mode is supported, so try using it and catch the error.
(define (mode-ok? mode)
  (with-handlers ([exn:fail? (lambda (e) #f)])
    (begin (gcry_cipher_close (gcry_cipher_open GCRY_CIPHER_AES mode 0)) #t)))
(define gcm-ok? (mode-ok? GCRY_CIPHER_MODE_GCM))
(define ocb-ok? (mode-ok? GCRY_CIPHER_MODE_OCB))

(define (cipher-spec-ok? spec)
  ;; Additional mode compat checks
  (match-define (list cipher mode) spec)
  (and (case mode
         [(gcm) gcm-ok?]
         [(ocb) ocb-ok?]
         [else #t])
       (case mode
         [(ccm gcm ocb xts eax)
          (memq cipher '(aes twofish serpent camellia))]
         [else #t])))

;; ----------------------------------------

(define (gcrypt-fetch-digest factory info)
  (define xof? (eq? ($di-size* info) 'vz))
  (match ($get-spec info)
    [(? symbol? dspec)
     (define algid (get-digest-algid dspec))
     (and algid (let ([inner (gcrypt-digest-inner-impl algid #f xof?)])
                  (make-digest info factory inner)))]
    [(list 'hmac dspec)
     (define algid (get-digest-algid dspec))
     (and algid (let ([inner (gcrypt-digest-inner-impl algid #t #f)])
                  (make-digest info factory inner)))]
    [_ #f]))

(define (gcrypt-fetch-cipher factory info)
  (define spec ($get-spec info))
  (define aead? ($ci-aead? info))
  (define (algid->llci algid mode-id)
    (and (gcry_cipher_test_algo algid)
         (gcrypt-lowlevel-cipher-impl algid mode-id aead?)))
  (define (multi->cipher keylens+algids mode-id)
    (match keylens+algids
      [(? list?)
       (make-multikeylen-cipher
        info factory
        (for/list ([keylen (in-list (map car keylens+algids))]
                   [algid (in-list (map cadr keylens+algids))])
          (cons (quotient keylen 8) (algid->llci algid mode-id))))]
      [(? exact-integer? algid)
       (make-cipher info factory (algid->llci algid mode-id))]))
  (and (cipher-spec-ok? spec)
       (match spec
         [(list cipher-name 'stream)
          (match (assq cipher-name stream-ciphers)
            [(list _ keylens+algids mode-id)
             (multi->cipher keylens+algids mode-id)]
            [#f #f])]
         [(list cipher-name block-mode)
          (match (assq cipher-name block-ciphers)
            [(list _ keylens+algids)
             (match (assq block-mode block-modes)
               [(list _ mode-id)
                (multi->cipher keylens+algids mode-id)]
               [#f #f])]
            [#f #f])])))

(define (gcrypt-fetch-kdf factory info)
  (define spec ($get-spec info))
  (match spec
    [(list 'pbkdf2 'hmac dspec)
     (define algid (get-digest-algid dspec))
     (and algid (make-kdf info factory (gcrypt-pbkdf2-inner-impl algid)))]
    ['scrypt
     (make-kdf info factory (gcrypt-scrypt-inner-impl))]
    [(or 'argon2d 'argon2i 'argon2id)
     #:when v1.10/later?
     (make-kdf info factory (gcrypt-argon2-inner-impl))]
    [(list 'hkdf dspec)
     #:when v1.11/later?
     (match (assq dspec digests)
       [(list _ algid blocksize hmac-algid)
        (and hmac-algid (gcry_md_test_algo algid)
             (make-kdf info (gcrypt-hkdf-inner-impl hmac-algid)))]
       [#f #f])]
    [_ #f]))

(define (gcrypt-fetch-pk factory info)
  (define spec ($get-spec info))
  (case spec
    [(rsa) (gcrypt-rsa-impl info factory)]
    [(dsa) (gcrypt-dsa-impl info factory)]
    [(ec)  (gcrypt-ec-impl info factory)]
    [(eddsa) (and ed25519-ok? (gcrypt-eddsa-impl info factory))]
    [(ecx) (and x25519-ok? (gcrypt-ecx-impl info factory))]
    [else #f]))

;; ----------------------------------------

(define gcrypt-factory
  (make-factory
   #:name 'gcrypt
   #:version (version->list (gcry_check_version #f))
   #:ok? gcrypt-ok?
   #:load-error gcrypt-load-error

   #:get-digest gcrypt-fetch-digest
   #:get-cipher gcrypt-fetch-cipher
   #:get-kdf gcrypt-fetch-kdf
   #:get-pk gcrypt-fetch-pk))

#|

    ;; ----

    (define/override (info key)
      (case key
        [(all-ec-curves) gcrypt-curves]
        [(all-eddsa-curves)
         (append (if ed25519-ok? '(ed25519) '()) (if ed448-ok? '(ed448) '()))]
        [(all-ecx-curves)
         (append (if x25519-ok? '(x25519) '()) (if x448-ok? '(x448) '()))]
        [else (super info key)]))

    (define/override (print-lib-info)
      (super print-lib-info)
      (printf " version string: ~s\n" (gcry_check_version #f)))
    ))
|#
