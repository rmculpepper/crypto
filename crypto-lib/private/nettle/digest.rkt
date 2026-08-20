;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/digest.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide nettle-fetch-digest)

(define (nettle-fetch-digest factory info)
  (define spec ($get-spec info))
  (define inner
    (match spec
      ['shake128 (nettle-shake128-inner-impl)]
      ['shake256 (nettle-shake256-inner-impl)]
      [(? symbol? dspec)
       (let ([nh (lookup-nh dspec)])
         (and nh (nettle-digest-inner-impl nh)))]
      [(list 'hmac dspec)
       (let ([nh (lookup-nh dspec)])
         (and nh (nettle-hmac-inner-impl nh)))]
      [_ #f]))
  (make-digest info factory inner))

(define digests
  `(;;[Name     String]
    [md2       "md2"]
    [md4       "md4"]
    [md5       "md5"]
    [ripemd160 "ripemd160"]
    [sha1      "sha1"]
    [sha224    "sha224"]
    [sha256    "sha256"]
    [sha384    "sha384"]
    [sha512    "sha512"]
    [sha512/224 "sha512_224"]
    [sha512/256 "sha512_256"]
    [sha3-224  "sha3_224"]
    [sha3-256  "sha3_256"]
    [sha3-384  "sha3_384"]
    [sha3-512  "sha3_512"]
    ))

(define (lookup-nh dspec)
  (match (assq dspec digests)
    [(list _ algid)
     (match (assoc algid nettle-hashes)
       [(list _ nh) nh]
       [#f #f])]
    [#f #f]))

;; ----------------------------------------

(define (make-ctx size)
  (let ([ctx (malloc size 'atomic-interior)])
    (cpointer-push-tag! ctx HASH_CTX-tag)
    ctx))

(struct nettle-digest-inner-impl
  (nh       ;; nettle_hash
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs nettle-digest-inner-impl)

   #;(begin
       (define size (nettle_hash-digest_size nh))
       (define block-size (nettle_hash-block_size nh))
       (sanity-check #:size size #:block-size block-size))

   (define (%dii-new-ctx1 self ci key)
     (define nh (.nh self))
     (let ([ctx (make-ctx (nettle_hash-context_size nh))])
       ((nettle_hash-init nh) ctx)
       ctx))

   (define (%dii-update self ic buf start end)
     ((nettle_hash-update (.nh self)) ic (- end start) (ptr-add buf start)))

   (define (%dii-final self ic size)
     (define nh (.nh self))
     (define buf (make-bytes size))
     ((nettle_hash-digest nh) ic size buf)
     #;((nettle_hash-init nh) ic)
     buf)

   (define (%dii-copy self ic)
     (define ic-size (nettle_hash-context_size (.nh self)))
     (define ic2 (make-ctx ic-size))
     (memmove ic2 ic ic-size)
     ic2)
   ))

;; ----------------------------------------

(struct hmac-ic (outer inner ctx))

(struct nettle-hmac-inner-impl
  (nh
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs nettle-hmac-inner-impl)

   (define (%dii-new-ctx1 self di key)
     (define size (nettle_hash-context_size (.nh self)))
     (define outer (make-ctx size))
     (define inner (make-ctx size))
     (define ctx (make-ctx size))
     (nettle_hmac_set_key outer inner ctx (.nh self) key)
     (hmac-ic outer inner ctx))

    (define (%dii-update self ic buf start end)
      (nettle_hmac_update (hmac-ic-ctx ic) (.nh self) (ptr-add buf start) (- end start)))

    (define (%dii-final self ic size)
      (match-define (hmac-ic outer inner ctx) ic)
      (define buf (make-bytes size))
      (nettle_hmac_digest outer inner ctx (.nh self) buf (bytes-length buf))
      buf)

    (define (%dii-copy self ic)
      (match-define (hmac-ic outer inner ctx) ic)
      (define size (nettle_hash-context_size (.nh self)))
      (define ctx2 (make-ctx size))
      (memmove ctx2 ctx size)
      (hmac-ic outer inner ctx2))
    ))

;; ----------------------------------------

(struct nettle-shake-inner-impl
  (block_size
   ctx_size
   ctx_init
   ctx_update
   ctx_final
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs nettle-shake-inner-impl)

   (define (%dii-new-ctx1 self di key)
     (define ctx (make-ctx (.ctx_size self)))
     ((.ctx_init self) ctx)
     ctx)

   (define (%dii-update self ic buf start end)
     ((.ctx_update self) ic (- end start) (ptr-add buf start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     ((.ctx_final self) ctx (bytes-length buf) buf)
     buf)

   (define (%dii-copy self ic)
     (define ic2 (make-ctx (.ctx_size self)))
     (memmove ic2 ctx (.ctx_size self))
     ic2)
   ))

(define (nettle-shake128-inner-impl)
  (nettle-shake-inner-impl sha3_128_block_size
                           sha3_128_ctx_size
                           nettle_sha3_128_init
                           nettle_sha3_128_update
                           nettle_sha3_128_shake))

(define (nettle-shake256-inner-impl)
  (nettle-shake-inner-impl sha3_256_block_size
                           sha3_256_ctx_size
                           nettle_sha3_256_init
                           nettle_sha3_256_update
                           nettle_sha3_256_shake))
