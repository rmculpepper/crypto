;; Copyright 2018-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/digest.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide sodium-fetch-digest)

(define (sodium-fetch-digest factory info)
  (define spec ($get-spec info))
  (define inner
    (match ($get-spec info)
      [(? symbol? dspec)
       (case dspec
         [(sha256) (and sha256-ok? (sodium-sha256-inner-impl))]
         [(sha512) (and sha512-ok? (sodium-sha512-inner-impl))]
         [(shake128) (and shake128-ok? (sodium-shake128-inner-impl))]
         [(shake256) (and shake256-ok? (sodium-shake256-inner-impl))]
         [(blake2b-512 blake2b-384 blake2b-256 blake2b-160)
          (sodium-blake2-inner-impl)]
         [else #f])]
      [(list 'hmac dspec)
       (case dspec
         [(sha256) (and sha256-ok? (sodium-hmac-sha256-inner-impl))]
         [(sha512) (and sha512-ok? (sodium-hmac-sha512-inner-impl))]
         [else #f])]
      [_ #f]))
  (make-digest info factory inner))

;; ============================================================

(define (make-ctx size [initialize void])
  (define ctx (malloc size 'atomic-interior))
  (initialize ctx)
  ctx)

(define (copy-ctx ctx size)
  (define ctx2 (make-ctx size))
  (memmove ctx2 ctx size)
  ctx2)

;; ----------------------------------------

(struct sodium-blake2-inner-impl ()
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])

   (define (%dii-digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     (crypto_generichash_blake2b outbuf size (ptr-add buf start) (- end start) #"" 0)
     outbuf)

   (define (%dii-new-ctx2 self di key config)
     (define-values (salt custom)
       (check/ref-config '(salt custom) config config:blake2b #:in di))
     (define keylen (bytes-length key))
     (define size ($di-size di))
     (define ic (make-ctx (crypto_generichash_blake2b_statebytes)))
     (cond [(and (zero? (bytes-length salt))
                 (zero? (bytes-length custom)))
            (crypto_generichash_blake2b_init ic key keylen size)]
           [else
            (define salt* (make-sized-copy salt crypto_generichash_blake2b_SALTBYTES))
            (define custom* (make-sized-copy custom crypto_generichash_blake2b_PERSONALBYTES))
            (crypto_generichash_blake2b_init_salt_personal ic key keylen salt* custom*)])
     (values ic size))

   (define (%dii-update self ic buf start end)
     (crypto_generichash_blake2b_update ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (crypto_generichash_blake2b_final ic buf size)
     buf)

   (define (%dii-copy self ic)
     (copy-ctx ic (crypto_generichash_blake2b_statebytes)))
   ))

;; ----------------------------------------

(struct sodium-digest-inner-impl
  (digest_buffer
   ctx_size
   ctx_init
   ctx_update
   ctx_final)
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs sodium-digest-inner-impl)

   (define (%dii-digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     ((.digest_buffer self) outbuf (ptr-add buf start) (- end start))
     outbuf)

   (define (%dii-new-ctx1 self di key)
     (make-ctx (.ctx_size self) (.ctx_init self)))

   (define (%dii-update self ic buf start end)
     ((.ctx_update self) ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     ((.ctx_final self) ic buf))

   (define (%dii-copy self ic)
     (copy-ctx ic (.ctx_size self)))
   ))

(define (sodium-sha256-inner-impl)
  (sodium-digest-inner-impl crypto_hash_sha256
                            (crypto_hash_sha256_statebytes)
                            crypto_hash_sha256_init
                            crypto_hash_sha256_update
                            crypto_hash_sha256_final))

(define (sodium-sha512-inner-impl)
  (sodium-digest-inner-impl crypto_hash_sha512
                            (crypto_hash_sha512_statebytes)
                            crypto_hash_sha512_init
                            crypto_hash_sha512_update
                            crypto_hash_sha512_final))

;; ----------------------------------------

(struct sodium-hmac-inner-impl
  (ctx_size
   ctx_init
   ctx_update
   ctx_final)
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs sodium-hmac-inner-impl)

   ;; no digest-buffer; sodium function does not take keylen arg

   (define (%dii-new-ctx1 self di key)
     (define ic (make-ctx (.ctx_size self)))
     ((.ctx_init self) ic key (bytes-length key))
     ic)

   (define (%dii-update self ic buf start end)
     ((.ctx_update self) ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     ((.ctx_final self) ic buf)
     buf)

   (define (%dii-copy self ic)
     (copy-ctx ic (.ctx_size self)))
   ))

(define (sodium-hmac-sha256-inner-impl)
  (sodium-hmac-inner-impl (crypto_auth_hmacsha256_statebytes)
                          crypto_auth_hmacsha256_init
                          crypto_auth_hmacsha256_update
                          crypto_auth_hmacsha256_final))

(define (sodium-hmac-sha512-inner-impl)
  (sodium-hmac-inner-impl (crypto_auth_hmacsha512_statebytes)
                          crypto_auth_hmacsha512_init
                          crypto_auth_hmacsha512_update
                          crypto_auth_hmacsha512_final))

;; ----------------------------------------

(struct sodium-xof-inner-impl
  (digest_buffer
   ctx_size
   ctx_init
   ctx_update
   ctx_final)
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs sodium-xof-inner-impl)

   (define (%dii-digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     ((.digest_buffer self) outbuf size (ptr-add buf start) (- end start))
     outbuf)

   (define (%dii-new-ctx1 self di key)
     (make-ctx (.ctx_size self) (.ctx_init self)))

   (define (%dii-update self ic buf start end)
     ((.ctx_update self) ic (ptr-add buf start) (- end start)))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     ((.ctx_final self) ic buf size))

   (define (%dii-copy self ic)
     (copy-ctx ic (.ctx_size self)))
   ))

(define (sodium-shake128-inner-impl)
  (sodium-xof-inner-impl crypto_xof_shake128
                         (crypto_xof_shake128_statebytes)
                         crypto_xof_shake128_init
                         crypto_xof_shake128_update
                         crypto_xof_shake128_squeeze))

(define (sodium-shake256-inner-impl)
  (sodium-xof-inner-impl crypto_xof_shake256
                         (crypto_xof_shake128_statebytes)
                         crypto_xof_shake128_init
                         crypto_xof_shake128_update
                         crypto_xof_shake128_squeeze))
