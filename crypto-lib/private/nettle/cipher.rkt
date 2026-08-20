;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         brandx
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/cipher.rkt"
         "../common/error.rkt"
         "../common/util.rkt"
         "ffi.rkt")
(provide nettle-fetch-cipher)

(define (nettle-fetch-cipher factory info)
  (define spec ($get-spec info))
  (define (alg->cipher alg mode)
    (cond [(string? alg)
           (make-cipher info factory (make-llci alg mode))]
          [(list? alg)
           (make-multikeylen-cipher
            info factory
            (for/list ([keylen (in-list (map car alg))]
                       [algid (in-list (map cadr alg))])
              (cons (quotient keylen 8)
                    (make-llci algid mode))))]))
  (match spec
    [(list cipher-name 'stream)
     (match (assq cipher-name stream-ciphers)
       [(list _ algid)
        (alg->cipher algid 'stream)]
       [#f #f])]
    [(list cipher-name block-mode)
     (match (assq cipher-name block-ciphers)
       [(list _ gcm/eax-ok? alg)
        (and (memq block-mode block-modes)
             (if (memq block-mode '(gcm eax)) gcm/eax-ok? #t)
             (alg->cipher alg block-mode))]
       [#f #f])]))

(define (make-llci algid mode)
  (match (assoc algid nettle-all-ciphers)
    [(list _ nc) (nettle-lowlevel-cipher-impl nc mode)]
    [#f #f]))

;; ----------------------------------------

(define block-ciphers
  `(;;[Name GCMok? String/([KeySize String] ...)]
    [aes #t ([128 "aes128"]
             [192 "aes192"]
             [256 "aes256"])]
    [blowfish #f "blowfish"]
    [camellia #t ([128 "camellia128"]
                  [192 "camellia192"]
                  [256 "camellia256"])]
    [cast128 #f ([128 "cast128"])]
    [serpent #t ([128 "serpent128"]
                 [192 "serpent192"]
                 [256 "serpent256"])]
    [twofish #t ([128 "twofish128"]
                 [192 "twofish192"]
                 [256 "twofish256"])]))

(define block-modes `(ecb cbc ctr ,@(if gcm-ok? '(gcm) '()) ,@(if eax-ok? '(eax) '())))

(define stream-ciphers
  `(;;[Name String/([KeySize String] ...)]
    [salsa20 "salsa20"]
    [salsa20r12 "salsa20r12"]
    [chacha20 "chacha"]
    [rc4 "arcfour128"]
    [chacha20-poly1305 "chacha-poly1305"]
    ;; "arctwo40", "arctwo64", "arctwo128"
    ))

;; ============================================================

(define (make-tagged-mem size tag)
  (let ([mem (malloc size 'atomic-interior)])
    (cpointer-push-tag! mem tag)
    mem))

(define (make-ctx size) (make-tagged-mem size CIPHER_CTX-tag))
(define (make-gcm_key)  (make-tagged-mem GCM_KEY_SIZE gcm_key-tag))
(define (make-gcm_ctx)  (make-tagged-mem GCM_CTX_SIZE gcm_ctx-tag))
(define (make-eax_key) (make-tagged-mem EAX_KEY_SIZE eax_key-tag))
(define (make-eax_ctx) (make-tagged-mem EAX_CTX_SIZE eax_ctx-tag))

;; ----------------------------------------

(struct nettle-llc (ctx ekey ectx))

(struct nettle-lowlevel-cipher-impl
  (nc mode)
  #:properties
  (method-properties
   #:export ([lowlevel-cipher-impl$ #:prefix %])
   (define-struct-abbrevs nettle-lowlevel-cipher-impl)

   (define (%llci-new-ctx self key iv enc? auth-len)
     (define nc (.nc self))
     (define ctx (make-ctx (nettle-cipher-context-size nc)))
     (if (or enc? (memq (.mode self) '(ctr gcm eax)))
         ((nettle-cipher-set-encrypt-key nc) ctx key)
         ((nettle-cipher-set-decrypt-key nc) ctx key))
     (let ([set-iv (nettle-cipher-ref nc 'set-iv)])
       (when set-iv (set-iv ctx iv)))
     (case (.mode self)
       [(gcm)
        (define gcm-key (make-gcm_key))
        (define gcm-ctx (make-gcm_ctx))
        ;; GCM uses block cipher's encrypt
        (nettle_gcm_set_key gcm-key ctx (nettle-cipher-encrypt nc))
        (nettle_gcm_set_iv  gcm-ctx gcm-key (bytes-length iv) iv)
        (nettle-llc ctx gcm-key gcm-ctx)]
       [(eax)
        (define eax-key (make-eax_key))
        (define eax-ctx (make-eax_ctx))
        ;; EAX uses block cipher's encrypt
        (nettle_eax_set_key eax-key ctx (nettle-cipher-encrypt nc))
        (nettle_eax_set_nonce eax-ctx eax-key ctx (nettle-cipher-encrypt nc)
                              (bytes-length iv) iv)
        (nettle-llc ctx eax-key eax-ctx)]
       [(cbc ctr)
        (define llc-iv (make-bytes (nettle-cipher-block-size nc)))
        (when (positive? (bytes-length llc-iv))
          (bytes-copy! llc-iv 0 iv 0 (bytes-length llc-iv)))
        (nettle-llc ctx #f llc-iv)]
       [else
        (nettle-llc ctx #f #f)]))

   (define (%llci-aad self llc buf start end)
     (define nc (.nc self))
     (match-define (nettle-llc ctx ekey ectx) llc)
     (case (.mode self)
       [(gcm)
        (nettle_gcm_update ectx ekey (- end start) (ptr-add buf start))]
       [(eax)
        (nettle_eax_update ectx ekey ctx (nettle-cipher-encrypt nc)
                           (- end start) (ptr-add buf start))]
       [else
        (let ([update-aad (nettle-cipher-ref (.nc self) 'update-aad)])
          (unless update-aad (internal-error "cannot update AAD" #:in self))
          (update-aad ctx (- end start) (ptr-add buf start)))]))

   (define (%llci-crypt self llc enc? final? buf start end outbuf)
     (define nc (.nc self))
     (match-define (nettle-llc ctx ekey ectx) llc)
     (case (.mode self)
       [(gcm)
        ;; Note: must use *encrypt* function in GCM mode
        (define crypt (nettle-cipher-encrypt nc))
        (define gcm*crypt (if enc? nettle_gcm_encrypt nettle_gcm_decrypt))
        (gcm*crypt ectx ekey ctx crypt (- end start) outbuf (ptr-add buf start))]
       [(eax)
        ;; Note: must use *encrypt* function in EAX mode
        (define crypt (nettle-cipher-encrypt nc))
        (define eax*crypt (if enc? nettle_eax_encrypt nettle_eax_decrypt))
        (eax*crypt ectx ekey ctx crypt (- end start) outbuf (ptr-add buf start))]
       [(ecb stream)
        (define crypt (if enc? (nettle-cipher-rkt-encrypt nc) (nettle-cipher-rkt-decrypt nc)))
        (crypt ctx (- end start) outbuf (ptr-add buf start))]
       [(cbc)
        (define crypt (if enc? (nettle-cipher-encrypt nc) (nettle-cipher-decrypt nc)))
        (define cbc_*crypt (if enc? nettle_cbc_encrypt nettle_cbc_decrypt))
        (define chunk-size (nettle-cipher-block-size nc))
        (cbc_*crypt ctx crypt chunk-size ectx (- end start) outbuf (ptr-add buf start))]
       [(ctr)
        ;; Note: must use *encrypt* function in CTR mode, even when decrypting
        (define crypt (nettle-cipher-encrypt nc))
        (define chunk-size (nettle-cipher-block-size nc))
        (nettle_ctr_crypt ctx crypt chunk-size ectx (- end start) outbuf (ptr-add buf start))]
       [else (internal-error "bad mode: ~e" (.mode self) #:in self)])
     (- end start))

   (define (%llci-encrypt-end self llc auth-len)
     (get-auth-tag self llc auth-len))

   (define (%llci-decrypt-end self llc auth-tag)
     (define actual-tag (get-auth-tag self llc (bytes-length auth-tag)))
     (unless (crypto-bytes=? auth-tag actual-tag)
       (err/auth-decrypt-failed)))

   (define (get-auth-tag self llc taglen)
     (define nc (.nc self))
     (match-define (nettle-llc ctx ekey ectx) llc)
     (define tag (make-bytes taglen))
     (case (.mode self)
       [(gcm)
        (nettle_gcm_digest ectx ekey ctx (nettle-cipher-encrypt nc) taglen tag)]
       [(eax)
        (nettle_eax_digest ectx ekey ctx (nettle-cipher-encrypt nc) taglen tag)]
       [else
        (cond [(zero? taglen) (void)]
              [(nettle-cipher-ref nc 'get-auth-tag)
               => (lambda (get-auth-tag) (get-auth-tag ctx taglen tag))]
              [else (internal-error "cannot get auth tag" #:in self)])])
     tag)

   (define (%llci-close self llc)
     (void))
   ))
