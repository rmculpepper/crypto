;; Copyright 2026 Ryan Culpepper
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
(provide libcrypto3-fetch-digest
         get-digest-lcname)

(define digests-3.0
  #hasheq([md2       . "md2"]
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
          [blake2b-512 . ("blake2b-512" "blake2bmac" #f)]
          [blake2s-256 . ("blake2s-256" "blake2smac" #f)]
          [shake128 . "shake128"]
          [shake256 . "shake256"]
          ))

;; Support for blake2b "size" param added in v3.2
(define digests-3.2
  (hash-set* digests-3.0
             'blake2b     '("blake2b-512" "blake2bmac" #f)
             'blake2b-384 '("blake2b-512" "blake2bmac" 48)
             'blake2b-256 '("blake2b-512" "blake2bmac" 32)
             'blake2b-160 '("blake2b-512" "blake2bmac" 20)))

;; Support for blake2s "size" param added in v3.3
(define digests-3.3
  (hash-set* digests-3.2
             'blake2s     '("blake2s-256" "blake2smac" #f)
             'blake2s-224 '("blake2s-256" "blake2smac" 28)
             'blake2s-160 '("blake2s-256" "blake2smac" 20)
             'blake2s-128 '("blake2s-256" "blake2smac" 16)))

(define digests-table
  (cond [(version>=? libcrypto3-version '(3 3)) digests-3.3]
        [(version>=? libcrypto3-version '(3 2)) digests-3.2]
        [else digests-3.0]))

(define (get-digest-lcname dspec)
  ;; Does not guarantee that digest is available from libctx.
  (match (hash-ref digests-table dspec #f)
    [(? string? name-string) name-string]
    [(list dname macname #f) dname]
    [_ #f]))

;; ----------------------------------------

(define (libcrypto3-fetch-digest factory info)
  (define libctx ($factory-inner-ctx factory))
  (define spec ($get-spec info))
  (define xof? (eq? ($di-size* info) 'vz))
  (define inner
    (match spec
      [(? symbol?)
       (match (hash-ref digests-table spec #f)
         [(? string? name-string)
          (define md (NOERR (EVP_MD_fetch libctx name-string #f)))
          (and md (libcrypto3-digest-inner-impl xof? md #f #f))]
         [(list dname macname size)
          (define md (NOERR (EVP_MD_fetch libctx dname #f)))
          (define mac (and macname (NOERR (EVP_MAC_fetch libctx macname #f))))
          (and md (libcrypto3-digest-inner-impl xof? md mac size))]
         [#f #f])]
      [(list 'hmac dspec)
       (match (hash-ref digests-table dspec #f)
         [(? string? name-string)
          (define md (NOERR (EVP_MD_fetch libctx name-string #f)))
          (define hmac (HANDLEp (EVP_MAC_fetch libctx "HMAC" #f)))
          (and md hmac (libcrypto3-hmac-inner-impl #f hmac md))]
         [(list dname _ #f)
          (define md (NOERR (EVP_MD_fetch libctx dname #f)))
          (define hmac (HANDLEp (EVP_MAC_fetch libctx "HMAC" #f)))
          (and md hmac (libcrypto3-hmac-inner-impl #f hmac md))]
         [_
          ;; No way to propagate nonstandard size to HMAC digest,
          ;; so fall back to Racket impl.
          #f])]))
  (make-digest info factory inner))

;; ------------------------------------------------------------

(struct libcrypto3-inner-impl-base
  (xof?
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs libcrypto3-inner-impl-base)

   (define (%dii-update self ic buf start end)
     (match ic
       [(? EVP_MD_CTX?)
        (HANDLEp (EVP_DigestUpdate ic (ptr-add buf start) (- end start)))]
       [(? EVP_MAC_CTX?)
        (HANDLEp (EVP_MAC_update ic (ptr-add buf start) (- end start)))]))

   (define (%dii-final self ic size)
     (define buf (make-bytes size))
     (match ic
       [(? EVP_MD_CTX?)
        (if (.xof? self)
            (HANDLEp (EVP_DigestFinalXOF ic buf size))
            (HANDLEp (EVP_DigestFinal_ex ic buf)))]
       [(? EVP_MAC_CTX?)
        (if (.xof? self)
            (HANDLEp (EVP_MAC_finalXOF ic buf size))
            (HANDLEp (EVP_MAC_final ic buf size)))])
     buf)

   (define (%dii-copy self ic)
     (match ic
       [(? EVP_MD_CTX?)  (HANDLEp (EVP_MD_CTX_dup ic))]
       [(? EVP_MAC_CTX?) (HANDLEp (EVP_MAC_CTX_dup ic))]))
   ))

;; ----------------------------------------

(struct libcrypto3-digest-inner-impl libcrypto3-inner-impl-base
  (md       ;; EVP_MD
   mac      ;; EVP_MAC or #f
   size     ;; Nat or #f
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs libcrypto3-digest-inner-impl)

   ;; ----

   (define (%dii-digest-buffer self buf start end size)
     (if (.size self) #f (digest-buffer self buf start end size)))

   (define (digest-buffer self buf start end size)
     (define outbuf (make-bytes size))
     (HANDLEp (EVP_Digest (ptr-add buf start) (- end start) outbuf (.md self)))
     outbuf)

   (define (%dii-new-ctx2 self di key0 config)
     (match-define (libcrypto3-digest-inner-impl _ md size mac) self)
     (define key (or key0 #""))
     (define key? (not (zero? (bytes-length key))))
     (define-values (dsize params) (get-config-params self di key? config))
     (cond [(and key? mac)
            (define ic (HANDLEp (EVP_MAC_CTX_new mac)))
            (HANDLEp (EVP_MAC_init ic key (make-param-array params)))
            (values ic dsize)]
           [key?  ;; should be impossible
            (internal-error "key not supported (no MAC impl)" #:for di)]
           [else
            (define ic (HANDLEp (EVP_MD_CTX_new)))
            (HANDLEp (EVP_DigestInit_ex2 ic md (make-param-array params)))
            (values ic dsize)]))

   ;; get-config-params : Boolean Config -> (values Nat/#f ParamAlist)
   ;; Return size only if set by config, but use size field in params.
   (define (get-config-params self di key? config)
     (define config-family ($di-config-family di))
     (case config-family
       [(cshake)
        (define-values (function custom)
          (check/ref-config '(function custom) config config:cshake #:in di))
        (check-bytes "custom" custom 0 512 #:for "cshake" #:in di)
        (values #f
                `((#"function-name" octet-string ,function #:?)
                  (#"customization" octet-string ,custom #:?)))]
       [(blake2b blake2s)
        (define varsize? (and (memq ($get-spec di) '(blake2b blake2s)) #t))
        (define config-spec
          (case config-family
            [(blake2b) (if varsize? config:blake2b+size config:blake2b)]
            [(blake2s) (if varsize? config:blake2s+size config:blake2s)]))
        (define-values (csize salt custom)
          (check/ref-config '(size salt custom) config config-spec #:in di))
        (cond [key?
               (values csize
                       `((#"size"   uint         ,(or csize (.size self)) #:?)
                         (#"salt"   octet-string ,salt #:?)
                         (#"custom" octet-string ,custom #:?)))]
              [else
               ;; digest impl doesn't support salt, custom; MAC impl requires non-empty key
               (define (bad what)
                 (crypto-error "~a not supported with empty key" what #:in di))
               (unless (equal? salt #"") (bad "salt"))
               (unless (equal? custom #"") (bad "custom option"))
               (values csize
                       `((#"size" uint ,(or csize (.size self)) #:?)))])]
       [else
        (unless (null? config)
          (check-config config null #:in di))
        (values #f `((#"size" uint ,(.size self) #:?)))]))
   ))

#;
(sanity-check #:size (or size
                         (and (get-size) ;; not XOF or var-sized
                              (let ([size (EVP_MD_get_size md)])
                                (and (> size 0) size))))
              #:block-size (EVP_MD_get_block_size md))


;; ----------------------------------------

(struct libcrypto3-hmac-inner-impl libcrypto3-inner-impl-base
  (hmac
   md
   )
  #:properties
  (method-properties
   #:export ([digest-inner-impl$ #:prefix %])
   (define-struct-abbrevs libcrypto3-hmac-inner-impl)

   ;; ----

   (define (%dii-new-ctx1 self di key)
     (define ic (HANDLEp (EVP_MAC_CTX_new (.hmac self))))
     (define digest-name (EVP_MD_get0_name (.md self)))
     (define params (make-param-array `((#"digest" utf8-string ,digest-name))))
     (HANDLEp (EVP_MAC_init ic key params))
     ic)
   ))
