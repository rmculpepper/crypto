;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         scramble/bundle
         scramble/struct
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-fetch-cipher)

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

(struct gcrypt-lowlevel-cipher-impl
  (cipher mode aead?)
  #:properties
  (method-properties
   #:export ([lowlevel-cipher-impl$ #:prefix %])
   (define-struct-abbrevs gcrypt-lowlevel-cipher-impl)

   #;
   (define (sanity-check)
     (define key-size (gcry_cipher_get_algo_keylen cipher))
     (define chunk-size (gcry_cipher_get_algo_blklen cipher))
     __)

   (define (%llci-new-ctx self key iv enc? auth-len)
     (define ctx (gcry_cipher_open (.cipher self) (.mode self) 0))
     (gcry_cipher_setkey ctx key (bytes-length key))
     (when (positive? (bytes-length iv)) ;; (positive? iv-size)
       (if (= (.mode self) GCRY_CIPHER_MODE_CTR)
           (gcry_cipher_setctr ctx iv (bytes-length iv))
           (gcry_cipher_setiv ctx iv (bytes-length iv))))
     ctx)

   (define (%llci-aad self llc buf start end)
     (gcry_cipher_authenticate llc (ptr-add buf start) (- end start)))

   (define (%llci-crypt self llc enc? final? buf start end outbuf)
     (when final? (gcry_cipher_final llc))
     (define outlen (bytes-length outbuf))
     (if enc?
         (gcry_cipher_encrypt llc outbuf outlen (ptr-add buf start) (- end start))
         (gcry_cipher_decrypt llc outbuf outlen (ptr-add buf start) (- end start)))
     (- end start))

   (define (%llci-encrypt-end self llc auth-len)
     (cond [(positive? auth-len)
            (define tag (make-bytes auth-len))
            (gcry_cipher_gettag llc tag auth-len)
            tag]
           [else #""]))

   (define (%llci-decrypt-end self llc auth-tag)
     (when (.aead? self)
       (unless (= (gcry_cipher_checktag llc auth-tag (bytes-length auth-tag)) GPG_ERR_NO_ERROR)
         (err/auth-decrypt-failed))))

   (define (%llci-close self llc)
     (gcry_cipher_close llc))
   ))
