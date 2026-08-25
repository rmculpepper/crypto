;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require ffi/unsafe
         racket/match
         brandx
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "../common/util.rkt"
         "ffi.rkt")
(provide libcrypto3-fetch-cipher)

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

(define (libcrypto3-fetch-cipher factory info)
  (define libctx #f) ;; FIXME
  (define spec ($get-spec info))
  (match-define (list cipher-name mode) spec)
  (define evp/s
    (case mode
      [(stream)
       (match (assq cipher-name libcrypto-ciphers)
         [(list _ '(stream) #f name-string)
          (NOERR (EVP_CIPHER_fetch libctx name-string #f))]
         [_ #f])]
      [else
       (match (assq cipher-name libcrypto-ciphers)
         [(list _ modes keys name-string)
          #:when (memq mode modes)
          (cond [keys
                 (for/list ([key (in-list keys)])
                   (define s (format "~a-~a-~a" name-string key mode))
                   (cons (quotient key 8) (NOERR (EVP_CIPHER_fetch libctx s #f))))]
                [else
                 (define s (format "~a-~a" name-string mode))
                 (NOERR (EVP_CIPHER_fetch libctx s #f))])]
         [_ #f])]))
  (cond [(list? evp/s)
         (make-multikeylen-cipher
          info factory
          (for/list ([keylen+evp (in-list evp/s)] #:when (cdr keylen+evp))
            (match-define (cons keylen evp) keylen+evp)
            (cons keylen (libcrypto3-lowlevel-cipher-impl info evp))))]
        [evp/s (make-cipher info factory (libcrypto3-lowlevel-cipher-impl info evp/s))]
        [else #f]))

;; ------------------------------------------------------------

(struct libcrypto3-lowlevel-cipher-impl
  (info     ;; CipherSpec
   cipher   ;; EVP_CIPHER
   )
  #:properties
  (method-properties
   #:export ([lowlevel-cipher-impl$ #:prefix %])
   (define-struct-abbrevs libcrypto3-lowlevel-cipher-impl)

   (define (%llci-new-ctx self key iv enc? auth-len)
     (match-define (libcrypto3-lowlevel-cipher-impl info cipher) self)
     (define ic (HANDLEp (EVP_CIPHER_CTX_new)))
     (HANDLEp (EVP_CipherInit_ex2 ic cipher #f #f (if enc? 1 0) #f))
     ;; ----
     ;; Rather than mode/cipher case analysis, change if not default.
     (let ([keylen (bytes-length key)]
           [default-keylen (EVP_CIPHER_get_key_length cipher)])
       (unless (= keylen default-keylen)
         (HANDLEp (EVP_CIPHER_CTX_set_key_length ic keylen))))
     ;; Docs currently (2026-02) say to use ctrls for GCM, OCB, and based on my
     ;; reading of 3.0.5 src, ctrl forwards to params but not vice versa.
     (define mode ($ci-mode info))
     (case mode
       [(gcm)
        ;; No need (and not able) to set auth length. Just truncate tag.
        (set-iv-length ic iv)]
       [(ocb)
        (set-iv-length ic iv)
        (set-auth-length ic auth-len)]
       [(stream)
        (define cipher-name ($ci-cipher-name info))
        (case cipher-name
          [(chacha20)
           ;; libcrypto expects 16-byte IV: counter || nonce
           (set! iv (bytes-append (make-bytes (- 16 (bytes-length iv)) 0) iv))]
          [(chacha20-poly1305)
           (when (not enc?) (set-auth-length ic auth-len))]
          [else (void)])]
       [(ccm siv)
        (internal-error "unsupported")]
       [else (void)])
     ;; ----
     (HANDLEp (EVP_CipherInit_ex2 ic #f key iv -1 #f))
     (HANDLEp (EVP_CIPHER_CTX_set_padding ic 0))
     ic)

   (define (set-iv-length ic iv)
     (define ivlen (if iv (bytes-length iv) 0))
     (HANDLEp (EVP_CIPHER_CTX_ctrl ic EVP_CTRL_AEAD_SET_IVLEN ivlen #f)
              #:op "EVP_CTRL_AEAD_SET_IVLEN"))

   (define (set-auth-length ic auth-len)
     (HANDLEp (EVP_CIPHER_CTX_ctrl ic EVP_CTRL_AEAD_SET_TAG auth-len #f)
              #:op "EVP_CTRL_AEAD_SET_TAG, length only"))

   ;; ----

   (define (%llci-aad self ic buf start end)
     (HANDLEp (EVP_CipherUpdate ic #f (ptr-add buf start) (- end start))))

   (define (%llci-crypt self ic enc? final? buf start end outbuf)
     (HANDLEp (EVP_CipherUpdate ic outbuf (ptr-add buf start) (- end start))))

   (define (%llci-encrypt-end self ic auth-len)
     (define outbuf (make-bytes ($ci-chunk-size (.info self))))
     (define outlen (HANDLEp (EVP_CipherFinal_ex ic outbuf)))
     (unless (zero? outlen)
       (internal-error "unexpected output at end of encryption: ~e bytes" outlen))
     (define auth-tag (if (zero? auth-len) #"" (make-bytes auth-len)))
     (when ($ci-aead? (.info self))
       (HANDLEp (EVP_CIPHER_CTX_ctrl ic EVP_CTRL_AEAD_GET_TAG auth-len auth-tag)
                #:op "EVP_CTRL_AEAD_GET_TAG"))
     (HANDLEp (EVP_CIPHER_CTX_reset ic))
     auth-tag)

   (define (%llci-decrypt-end self ic auth-tag)
     (when auth-tag
       (define auth-len (bytes-length auth-tag))
       (HANDLEp (EVP_CIPHER_CTX_ctrl ic EVP_CTRL_AEAD_SET_TAG auth-len auth-tag)))
     (define outbuf (make-bytes ($ci-chunk-size (.info self))))
     (define outlen (or (NOERR (EVP_CipherFinal_ex ic outbuf))
                        (err/crypt-failed #f ($ci-aead? (.info self)))))
     (unless (zero? outlen)
       (internal-error "unexpected output at end of decryption: ~e bytes" outlen))
     (HANDLEp (EVP_CIPHER_CTX_reset ic)))

   (define (%llci-close self ic)
     (void))
   ))

#;
(cond [(equal? (get-spec) '(chacha20 stream))
       ;; libcrypto chacha20 takes combined (counter || nonce) as IV
       (sanity-check #:block-size (EVP_CIPHER_get_block_size cipher))]
      [else
       (sanity-check #:iv-size (EVP_CIPHER_get_iv_length cipher)
                     #:block-size (EVP_CIPHER_get_block_size cipher))])
