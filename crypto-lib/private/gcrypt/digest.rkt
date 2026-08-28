;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/digest.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-fetch-digest
         get-digest-algid
         digests)

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

(struct gcrypt-digest-inner-impl
  (md       ;; Int
   hmac?    ;; Boolean
   xof?     ;; Boolean
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs gcrypt-digest-inner-impl)

   #;
   (sanity-check #:size (gcry_md_get_algo_dlen md) #:block-size blocksize)

   (define (%dii-digest-buffer self buf start end size)
     ;; FIXME: switch to gcry_md_hash_buffers
     (cond [(.hmac? self) #f]
           [else
            (define outbuf (make-bytes size))
            (gcry_md_hash_buffer (.md self) outbuf (ptr-add buf start) (- end start))
            outbuf]))

   (define (%dii-new-ctx2 self ci key config)
     (define ic
       (cond [(.hmac? self) (gcry_md_open (.md self) GCRY_MD_FLAG_HMAC)]
             [else (gcry_md_open (.md self) 0)]))
     (case (digest-spec-config-family ($get-spec ci))
       [(cshake)
        (define-values (function custom)
          (check/ref-config '(function custom) config config:cshake #:in ci))
        (unless (and (zero? (bytes-length function)) (zero? (bytes-length custom)))
          (check-bytes 'function function 0 255 #:for "cshake" #:in ci)
          (check-bytes 'custom   custom   0 255 #:for "cshake" #:in ci)
          (gcry_md_cshake_customize ic (new-cshake_customization function custom)))]
       [(blake2b blake2s)
        (unless (null? config) (check-config config null #:in ci #:impl-limit? #t))]
       [else
        (unless (null? config) (check-config config null #:in ci))])
     (when key (gcry_md_setkey ic key (bytes-length key)))
     (values ic #f))

   (define (%dii-update self ic buf start end)
     (gcry_md_write ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (if (.xof? self)
         (gcry_md_extract ic buf size)
         (gcry_md_read ic buf size))
     (gcry_md_close ic)
     buf)

   (define (%dii-copy self ic)
     (gcry_md_copy ic))
   ))
