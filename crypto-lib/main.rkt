;; Copyright 2012-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract/base
         racket/match
         racket/random
         "private/common/interfaces.rkt"
         "private/common/catalog.rkt"
         "private/common/common.rkt"
         "private/common/error.rkt"
         (only-in "private/common/pk-format.rkt" parse-params parse-key)
         "private/common/util.rkt")

(provide crypto-factory?
         digest-spec?
         digest-impl?
         digest-ctx?
         cipher-spec?
         cipher-impl?
         cipher-ctx?
         pk-spec?
         pk-impl?
         pk-parameters?
         pk-key?
         kdf-spec?
         kdf-impl?
         (struct-out bytes-range)
         input/c

         security-strength/c
         security-level/c
         security-level->strength
         security-strength->level

         ;; util
         (recontract-out
          hex->bytes
          bytes->hex
          bytes->hex-string
          crypto-bytes=?)

         ;; racket/random
         crypto-random-bytes)

;; Common abbrevs
(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))
(define pad-mode/c boolean?)

;; ============================================================

(define (to-impl src0 [fail-ok? #f] #:lookup [lookup #f])
  (let loop ([src src0])
    (cond [(impl? src) src]
          [(ctx? src) (ctx-impl src)]
          [(and lookup (lookup src)) => values]
          [fail-ok? #f]
          [else (crypto-error "could not get implementation" #:for src0)])))

(define (to-info src0 [fail-ok? #f] #:lookup [lookup #f])
  (let loop ([src src0])
    (cond [(info? src) src]
          [(impl? src) ($get-info src)]
          [(ctx? src) (loop (ctx-impl ctx))]
          [(and lookup (lookup src)) => values]
          [fail-ok? #f]
          [else (crypto-error "could not get info" #:for src0)])))

;; ============================================================
;; Factories

(provide
 (contract-out
  [crypto-factories
   (parameter/c factories/c (listof crypto-factory?))]
  [get-factory
   (-> (or/c digest-impl? digest-ctx?
             cipher-impl? cipher-ctx?
             pk-impl? pk-parameters? pk-key?)
       crypto-factory?)]
  [factory-version
   (-> crypto-factory? (or/c (listof exact-nonnegative-integer?) #f))]
  [factory-print-info
   (-> crypto-factory? void?)]
  [get-digest
   (->* [digest-spec?] [factories/c] (or/c digest-impl? #f))]
  [get-cipher
   (->* [cipher-spec?] [factories/c] (or/c cipher-impl? #f))]
  [get-pk
   (->* [symbol?] [factories/c] (or/c pk-impl? #f))]
  [get-kdf
   (->* [kdf-spec?] [factories/c] (or/c kdf-impl? #f))]
  ))

(define factories/c (or/c crypto-factory? (listof crypto-factory?)))

;; coerce-list : (or/c X (listof X) -> (listof X)
(define (coerce-list xs) (if (list? xs) xs (list xs)))

;; crypto-factories : parameter of (listof factory<%>)
(define crypto-factories (make-parameter null coerce-list))

(define (get-factory v)
  (with-crypto-entry 'get-factory
    (cond [(impl? v) ($get-factory v)]
          [(ctx? v) ($get-factory (ctx-impl v))])))

(define (get-digest dspec [factory/s (crypto-factories)])
  (with-crypto-entry 'get-digest
    (for/or ([f (in-list (coerce-list factory/s))])
      ($fetch-digest f dspec))))

(define (get-cipher cspec [factory/s (crypto-factories)])
  (with-crypto-entry 'get-cipher
    (for/or ([f (in-list (coerce-list factory/s))])
      ($fetch-cipher f cspec))))

(define (get-pk pkspec [factory/s (crypto-factories)])
  (with-crypto-entry 'get-pk
    (for/or ([f (in-list (coerce-list factory/s))])
      ($fetch-pk f pkspec))))

(define (get-kdf kdfspec [factory/s (crypto-factories)])
  (with-crypto-entry 'get-kdf
    (for/or ([f (in-list (coerce-list factory/s))])
      ($fetch-kdf f kdfspec))))

(define (factory-print-info factory)
  ($factory-print factory)
  (void))

(define (factory-version factory)
  ($factory-version factory))


;; ============================================================
;; Digests

(provide
 (contract-out
  [digest-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?)
       (or/c exact-nonnegative-integer? #f))]
  [digest-block-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) exact-nonnegative-integer?)]
  [digest-security-strength
   (-> (or/c digest-spec? digest-impl? digest-ctx?) boolean? (or/c #f security-strength/c))]
  [digest
   (->* [digest/c input/c]
        [#:key (or/c bytes? #f)
         #:size (or/c exact-nonnegative-integer? #f)
         #:config config/c]
        bytes?)]
  [hmac
   (-> digest/c bytes? input/c bytes?)]
  [make-digest-ctx
   (->* [digest/c] [#:key (or/c bytes? #f) #:config config/c] digest-ctx?)]
  [digest-update
   (-> digest-ctx? input/c void?)]
  [digest-final
   (->* [digest-ctx?]
        [#:size (or/c exact-nonnegative-integer? #f)]
        bytes?)]
  [digest-copy
   (-> digest-ctx? (or/c digest-ctx? #f))]
  [digest-peek-final
   (->* [digest-ctx?]
        [#:size (or/c exact-nonnegative-integer? #f)]
        (or/c bytes? #f))]
  [make-hmac-ctx
   (-> digest/c bytes? digest-ctx?)]
  [generate-hmac-key
   (-> digest/c bytes?)]))

(define digest/c (or/c digest-spec? digest-impl?))
(define (-get-digest-impl o) (to-impl o #:lookup get-digest))
(define (-get-digest-info o) (to-info o #:lookup digest-spec->info))
(define (-get-digest-spec o) (let ([di (-get-digest-info o)]) (and di ($get-spec di))))

;; ----

(define (digest-size di)
  (with-crypto-entry 'digest-size
    ($di-size (-get-digest-info di))))
(define (digest-block-size di)
  (with-crypto-entry 'digest-block-size
    ($di-block-size (-get-digest-info di))))

(define (digest-security-strength di [cr? #t])
  (with-crypto-entry 'digest-security-strength
    ($di-security-strength (-get-digest-info di) cr?)))

;; ----

(define (make-digest-ctx di #:key [key #f] #:config [config null])
  (with-crypto-entry 'make-digest-ctx
    ($di-new-ctx (-get-digest-impl di) key config)))

(define (digest-update dctx src)
  (with-crypto-entry 'digest-update
    ($di-update (ctx-impl dctx) dctx src)))

(define (digest-final dctx #:size [size #f])
  (with-crypto-entry 'digest-final
    ($di-final (ctx-impl dctx) dctx size)))

(define (digest-copy dctx)
  (with-crypto-entry 'digest-copy
    ($di-copy (ctx-impl dctx) dctx)))

(define (digest-peek-final dctx #:size [size #f])
  (with-crypto-entry 'digest-peek-final
    (define dctx2 ($di-copy (ctx-impl dctx) dctx))
    (and dctx2 ($di-final (ctx-impl dctx2) dctx2 size))))

;; ----

(define (digest di inp #:key [key #f] #:size [size #f] #:config [config null])
  (with-crypto-entry 'digest
    (let ([di (-get-digest-impl di)])
      ($digest di inp key size config))))

;; ----

(define (make-hmac-ctx di key)
  (with-crypto-entry 'make-hmac-ctx
    (define hmacdi (-get-hmac-impl di))
    ($di-new-ctx hmacdi key null)))

(define (hmac di key inp)
  (with-crypto-entry 'hmac
    (define hmacdi (-get-hmac-impl di))
    ($digest hmacdi inp key #f null)))

(define (-get-hmac-impl di)
  (unless (digest-spec? `(hmac ,($get-spec di)))
    (crypto-error "HMAC not supported" #:in di))
  (cond [(digest-impl? di)
         (parameterize ((crypto-factories ($get-factory di)))
           (-get-digest-impl `(hmac ,($get-spec di))))]
        [(digest-spec? di)
         (-get-digest-impl `(hmac ,di))]))

;; ----

(define (generate-hmac-key di)
  (with-crypto-entry 'generate-hmac-key
    (define dsize (digest-size di))
    (unless dsize (err/not-fixed-digest di))
    (crypto-random-bytes dsize)))

;; ============================================================
;; Ciphers

(provide
 (contract-out
  [cipher-default-key-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-key-sizes
   (-> (or/c cipher-spec? cipher-impl?) (listof nat?))]
  [cipher-block-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-iv-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-aead?
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) boolean?)]
  [cipher-default-auth-size
   (-> (or/c cipher-spec? cipher-impl? cipher-ctx?) nat?)]
  [cipher-chunk-size
   (-> (or/c cipher-impl? cipher-ctx?) nat?)]

  [make-encrypt-ctx
   (->* [cipher/c key/c iv/c]
        [#:pad pad-mode/c #:auth-size (or/c nat? #f) #:auth-attached? boolean?]
        encrypt-ctx?)]
  [make-decrypt-ctx
   (->* [cipher/c key/c iv/c]
        [#:pad pad-mode/c #:auth-size (or/c nat? #f) #:auth-attached? boolean?]
        decrypt-ctx?)]
  [encrypt-ctx?
   (-> any/c boolean?)]
  [decrypt-ctx?
   (-> any/c boolean?)]
  [cipher-update
   (-> cipher-ctx? input/c bytes?)]
  [cipher-update-aad
   (-> cipher-ctx? input/c void?)]
  [cipher-final
   (->* [cipher-ctx?] [(or/c bytes? #f)] bytes?)]
  [cipher-get-auth-tag
   (-> cipher-ctx? (or/c bytes? #f))]

  [encrypt
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)]
        bytes?)]
  [decrypt
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)]
        bytes?)]

  [encrypt/auth
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-size (or/c nat? #f)]
        (values bytes? (or/c bytes? #f)))]
  [decrypt/auth
   (->* [cipher/c key/c iv/c input/c]
        [#:pad pad-mode/c #:aad input/c #:auth-tag (or/c bytes? #f)]
        bytes?)]

  [generate-cipher-key
   (->* [cipher/c] [#:size nat?] key/c)]
  [generate-cipher-iv
   (->* [cipher/c] [#:size nat?] iv/c)]))

(define cipher/c (or/c cipher-spec? cipher-impl?))

(define default-pad #t)

(define (-get-cipher-impl o) (to-impl o #:lookup get-cipher))
(define (-get-cipher-info o) (to-info o #:lookup cipher-spec->info))

;; ----

;; Defer to impl when avail to support unknown ciphers or impl-dependent limits.

(define (cipher-default-key-size o)
  (with-crypto-entry 'cipher-default-key-size
    ($ci-key-size (-get-cipher-info o))))
(define (cipher-key-sizes o)
  (with-crypto-entry 'cipher-key-sizes
    (size-set->list ($ci-key-sizes (-get-cipher-info o)))))
(define (cipher-block-size o)
  (with-crypto-entry 'cipher-block-size
    ($ci-block-size (-get-cipher-info o))))
(define (cipher-chunk-size o)
  (with-crypto-entry 'cipher-chunk-size
    ($ci-chunk-size (-get-cipher-info o))))
(define (cipher-iv-size o)
  (with-crypto-entry 'cipher-iv-size
    ($ci-iv-size (-get-cipher-info o))))
(define (cipher-aead? o)
  (with-crypto-entry 'cipher-aead?
    ($ci-aead? (-get-cipher-info o))))
(define (cipher-default-auth-size o)
  (with-crypto-entry 'cipher-default-auth-size
    ($ci-auth-size (-get-cipher-info o))))

;; ----

(define (encrypt-ctx? x)
  (and (cipher-ctx? x) (cipher-ctx-encrypt? x)))
(define (decrypt-ctx? x)
  (and (cipher-ctx? x) (cipher-ctx-encrypt? x)))

;; make-{en,de}crypt-ctx : ... -> cipher-ctx
;; auth-tag-size : Nat/#f -- #f means default tag size for cipher
(define (make-encrypt-ctx ci key iv #:pad [pad? #t]
                          #:auth-size [auth-size #f] #:auth-attached? [auth-attached? #t])
  (with-crypto-entry 'make-encrypt-ctx
    (-encrypt-ctx ci key iv pad? auth-size auth-attached?)))
(define (make-decrypt-ctx ci key iv #:pad [pad? #t]
                          #:auth-size [auth-size #f] #:auth-attached? [auth-attached? #t])
  (with-crypto-entry 'make-decrypt-ctx
    (-decrypt-ctx ci key iv pad? auth-size auth-attached?)))

(define (-encrypt-ctx ci key iv pad auth-size auth-attached?)
  (let ([ci (-get-cipher-impl ci)])
    ($ci-new-ctx ci key (or iv #"") #t pad auth-size auth-attached?)))
(define (-decrypt-ctx ci key iv pad auth-size auth-attached?)
  (let ([ci (-get-cipher-impl ci)])
    ($ci-new-ctx ci key (or iv #"") #f pad auth-size auth-attached?)))

(define (cipher-update-aad cctx inp)
  (with-crypto-entry 'cipher-update-aad
    ($ci-update-aad (ctx-impl cctx) cctx inp)))

(define (cipher-update cctx inp)
  (with-crypto-entry 'cipher-update
    ($ci-update (ctx-impl cctx) cctx inp)
    ($ci-get-output (ctx-impl cctx) cctx)))

(define (cipher-final cctx [auth-tag #f])
  (with-crypto-entry 'cipher-final
    ($ci-final (ctx-impl cctx) cctx auth-tag)
    ($ci-get-output (ctx-impl cctx) cctx)))

(define (cipher-get-auth-tag cctx)
  (with-crypto-entry 'cipher-get-auth-tag
    ($ci-auth-tag (ctx-impl cctx) cctx)))

;; ----

(define (encrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt
    (let ([ci (-get-cipher-impl ci)])
      (define cctx (-encrypt-ctx ci key iv pad auth-size #t))
      (define impl (ctx-impl cctx))
      ($ci-update-aad impl cctx aad-inp)
      ($ci-update impl cctx inp)
      ($ci-final impl cctx #f)
      ($ci-get-output impl cctx))))

(define (decrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-cipher-impl ci)])
      (define cctx (-decrypt-ctx ci key iv pad auth-size #t))
      (define impl (ctx-impl cctx))
      ($ci-update-aad impl cctx aad-inp)
      ($ci-update impl cctx inp)
      ($ci-final impl cctx #f)
      ($ci-get-output impl cctx))))

(define (encrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt/auth
    (let ([ci (-get-cipher-impl ci)])
      (define cctx (-encrypt-ctx ci key iv pad auth-size #f))
      (define impl (ctx-impl cctx))
      ($ci-update-aad impl cctx aad-inp)
      ($ci-update impl cctx inp)
      ($ci-final impl cctx #f)
      (values ($ci-get-output impl cctx)
              ($ci-auth-tag impl cctx)))))

(define (decrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-tag [auth-tag #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-cipher-impl ci)])
      (define auth-len (and auth-tag (bytes-length auth-tag)))
      (define cctx (-decrypt-ctx ci key iv pad auth-len #f))
      (define impl (ctx-impl cctx))
      ($ci-update-aad impl cctx aad-inp)
      ($ci-update impl cctx inp)
      ($ci-final impl cctx #f)
      ($ci-get-output impl cctx))))

;; ----

(define (generate-cipher-key ci #:size [size (cipher-default-key-size ci)])
  (with-crypto-entry 'generate-cipher-key
    ;; FIXME: any way to check for weak keys, avoid???
    (crypto-random-bytes size)))

(define (generate-cipher-iv ci #:size [size (cipher-iv-size ci)])
  (with-crypto-entry 'generate-cipher-iv
    (if (positive? size) (crypto-random-bytes size) #"")))


;; ============================================================
;; KDFs and Password Hashing

(provide
 (contract-out
  [kdf
   (->* [(or/c kdf-spec? kdf-impl?)
         bytes?
         (or/c bytes? #f)]
        [(listof (list/c symbol? any/c))
         #:key-size (or/c exact-nonnegative-integer? #f)]
        bytes?)]
  [pwhash
   (->* [(or/c kdf-spec? kdf-impl?) bytes?]
        [(listof (list/c symbol? any/c))]
        string?)]
  [pwhash-verify
   (-> (or/c kdf-impl? #f) bytes? string?
       boolean?)]
  [pbkdf2-hmac
   (->* [digest-spec? bytes? bytes? #:iterations exact-positive-integer?]
        [#:key-size exact-positive-integer?]
        bytes?)]
  [scrypt
   (->* [bytes?
         bytes?
         #:N exact-positive-integer?]
        [#:r exact-positive-integer?
         #:p exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  ))

(define (-get-kdf-impl o) (to-impl o #:lookup get-kdf))

(define (kdf k pass salt [params '()] #:key-size [key-size #f])
  (with-crypto-entry 'kdf
    (let ([k (-get-kdf-impl k)])
      ($kdf-derive k key-size params pass salt))))

(define (pwhash k pass [params '()])
  (with-crypto-entry 'pwhash
    (let ([k (-get-kdf-impl k)])
      ($pwhash k params pass))))

(define (pwhash-verify k pass cred)
  (with-crypto-entry 'pwhash-verify
    (define k* (or k (-get-kdf-impl (pwcred->kdf-spec cred))))
    ($pwhash-verify k* pass cred)))

(define (pwcred->kdf-spec cred)
  ;; see also crypto/private/rkt/pwhash
  (define m (regexp-match #rx"^[$]([a-z0-9-]*)[$]" cred))
  (define id (and m (string->symbol (cadr m))))
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2) '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [(#f) (crypto-error "invalid password hash format")]
    [else (crypto-error "unknown password hash identifier\n  id: ~e" id)]))

(define (pbkdf2-hmac di pass salt
                     #:iterations iterations
                     #:key-size [key-size (digest-size di)])
  (with-crypto-entry 'pbkdf2-hmac
    (let ([k (-get-kdf-impl `(pbkdf2 hmac ,di))])
      ($kdf-derive k key-size `((iterations ,iterations)) pass salt))))

(define (scrypt pass salt
                #:N N
                #:p [p 1]
                #:r [r 8]
                #:key-size [key-size 32])
  (with-crypto-entry 'scrypt
    (let ([k (-get-kdf-impl 'scrypt)])
      ($kdf-derive k key-size `((N ,N) (p ,p) (r ,r)) pass salt))))

;; ============================================================
;; Public-key Systems

(provide
 private-key?
 public-only-key?
 (contract-out
  [pk-can-sign?
   (->* [(or/c pk-spec? pk-impl? pk-key?)]
        [(or/c symbol? #f) (or/c symbol? #f)]
        boolean?)]
  [pk-can-encrypt?
   (->* [(or/c pk-spec? pk-impl? pk-key?)] [(or/c symbol? #f)] boolean?)]
  [pk-can-key-agree?
   (-> (or/c pk-spec? pk-impl? pk-key?) boolean?)]
  [pk-has-parameters?
   (-> (or/c pk-spec? pk-impl? pk-key?) boolean?)]

  [pk-security-strength
   (-> (or/c pk-key? pk-parameters?) (or/c #f security-strength/c))]

  [pk-key->parameters
   (-> pk-key? (or/c pk-parameters? #f))]

  [public-key=?
   (->* [pk-key?] [] #:rest (listof pk-key?) boolean?)]
  [pk-key->public-only-key
   (-> pk-key? public-only-key?)]

  [pk-key->datum
   (-> pk-key? symbol? any/c)]
  [datum->pk-key
   (->* [any/c symbol?]
        [(or/c pk-impl? crypto-factory? (listof (or/c pk-impl? crypto-factory?)))]
        pk-key?)]

  [pk-parameters->datum
   (-> pk-parameters? symbol? any/c)]
  [datum->pk-parameters
   (->* [any/c symbol?]
        [(or/c pk-impl? crypto-factory? (listof (or/c pk-impl? crypto-factory?)))]
        pk-parameters?)]

  [pk-sign
   (->* [private-key? bytes?]
        [#:digest (or/c digest-spec? #f 'none) #:pad sign-pad/c]
        bytes?)]
  [pk-verify
   (->* [pk-key? bytes? bytes?]
        [#:digest (or/c digest-spec? #f 'none) #:pad sign-pad/c]
        boolean?)]
  [pk-sign-digest
   (->* [private-key? (or/c digest-spec? digest-impl?) bytes?]
        [#:pad  sign-pad/c]
        bytes?)]
  [pk-verify-digest
   (->* [pk-key? (or/c digest-spec? digest-impl?) bytes? bytes?]
        [#:pad sign-pad/c]
        boolean?)]
  [digest/sign
   (->* [private-key? (or/c digest-spec? digest-impl?) input/c]
        [#:pad sign-pad/c]
        bytes?)]
  [digest/verify
   (->* [pk-key? (or/c digest-spec? digest-impl?) input/c bytes?]
        [#:pad sign-pad/c]
        boolean?)]

  [pk-encrypt
   (->* [pk-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]
  [pk-decrypt
   (->* [private-key? bytes?] [#:pad encrypt-pad/c]
        bytes?)]

  [pk-derive-secret
   (-> private-key? (or/c pk-key? bytes?)
       bytes?)]

  [generate-pk-parameters
   (->* [(or/c pk-spec? pk-impl?)] [config/c]
        pk-parameters?)]
  [generate-private-key
   (->* [(or/c pk-spec? pk-impl? pk-parameters?)] [config/c]
        private-key?)]))

(define encrypt-pad/c
  (or/c 'pkcs1-v1.5 'oaep 'none #f))
(define sign-pad/c
  (or/c 'pkcs1-v1.5 'pss 'pss* 'none #f))

(define key-format/c
  (or/c symbol? #f))

(define (-get-pk-impl pki) (to-impl pki #:lookup get-pk))
(define (-get-pk-info pk) (to-info pk #:lookup pk-spec->info))

;; ----------------------------------------

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? x)
  (and (pk-key? x) (pk-key-private? x)))
(define (public-only-key? x)
  (and (pk-key? x) (not (pk-key-private? x))))

(define (pk-can-sign? pk [pad #f] [dspec #f])
  (with-crypto-entry 'pk-can-sign?
    ($pk-can-sign? (-get-pk-info pk) pad dspec)))
(define (pk-can-encrypt? pk [pad #f])
  (with-crypto-entry 'pk-can-encrypt?
    ($pk-can-encrypt? (-get-pk-info pk) pad)))
(define (pk-can-key-agree? pk)
  (with-crypto-entry 'pk-can-key-agree?
    ($pk-can-key-agree? (-get-pk-info pk))))
(define (pk-has-parameters? pk)
  (with-crypto-entry 'pk-has-parameters?
    ($pk-has-params? (-get-pk-info pk))))

(define (pk-security-strength pk)
  (with-crypto-entry 'pk-security-strength
    (cond [(pk-key? pk) ($pkk-security-bits (ctx-impl pk) pk)]
          [(pk-parameters? pk) ($pkp-security-bits (ctx-impl pk) pk)])))

(define (pk-key->parameters pkk)
  (with-crypto-entry 'pk-key->parameters
    (and (pk-has-parameters? pkk)
         ($pkk-params (ctx-impl pkk) pkk))))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (with-crypto-entry 'public-key=?
    (define impl1 (ctx-impl k1))
    (for/and ([k2 (in-list ks)])
      (define impl2 (ctx-impl k2))
      (if (eq? impl1 impl2)
          ($pkk-equal-public? impl1 k1 k2)
          (pk-compare-key-data k1 k2 'internal-public)))))

(define (pk-key->datum pkk fmt)
  (with-crypto-entry 'pk-key->datum
    (or ($pkk-write-key (ctx-impl pkk) pkk fmt)
        (crypto-error "key format not supported\n  format: ~e"
                      fmt #:in pkk))))
(define (datum->pk-key datum fmt [src (crypto-factories)])
  (with-crypto-entry 'datum->pk-key
    (define parsed (parse-key fmt datum))
    (or (and parsed (for/or ([src (in-list (if (list? src) src (list src)))])
                      (import-parsed src parsed)))
        (crypto-error "unable to read key\n  format: ~e" fmt))))

(define (pk-parameters->datum pkp fmt)
  (with-crypto-entry 'pk-parameters->datum
    (or ($pkp-write-params (ctx-impl pkp) pkp fmt)
        (crypto-error "parameters format not supported\n  format: ~e"
                      fmt #:in pkp))))
(define (datum->pk-parameters datum fmt [src (crypto-factories)])
  (with-crypto-entry 'datum->pk-parameters
    (define parsed (parse-params fmt datum))
    (or (and parsed (for/or ([src (in-list (if (list? src) src (list src)))])
                      (import-parsed src parsed)))
        (crypto-error "unable to read parameters\n  format: ~e" fmt))))

(define (pk-key->public-only-key pkk)
  (with-crypto-entry 'pk-key->public-only-key
    ($pkk-public-key (ctx-impl pkk) pkk)))

;; ----------------------------------------

(define (pk-sign pkk msg #:digest [dspec #f] #:pad [pad #f])
  (with-crypto-entry 'pk-sign
    ($pkk-sign (ctx-impl pkk) pkk msg dspec pad)))

(define (pk-verify pkk msg sig #:digest [dspec #f] #:pad [pad #f])
  (with-crypto-entry 'pk-verify
    ($pkk-verify (ctx-impl pkk) pkk msg dspec pad sig)))

(define (pk-sign-digest pkk di dbuf #:pad [pad #f])
  (with-crypto-entry 'pk-sign-digest
    (define dspec (-get-digest-spec di))
    ($pkk-sign (ctx-impl pkk) pkk dbuf di pad)))

(define (pk-verify-digest pkk di dbuf sig #:pad [pad #f])
  (with-crypto-entry 'pk-verify-digest
    (define dspec (-get-digest-spec di))
    ($pkk-verify (ctx-impl pkk) pkk dbuf di pad sig)))

(define (digest/sign pkk di0 inp #:pad [pad #f])
  (with-crypto-entry 'digest/sign
    (define dspec (-get-digest-spec di0))
    (define di (get-digest dspec (get-factory pkk)))
    (unless di (err/missing-digest dspec))
    (unless (digest-size di) (err/not-fixed-digest di #:in pkk))
    ($pkk-sign (ctx-impl pkk) pkk (digest di inp) dspec pad)))

(define (digest/verify pkk di0 inp sig #:pad [pad #f])
  (with-crypto-entry 'digest/verify
    (define dspec (-get-digest-spec di0))
    (define di (get-digest dspec (get-factory pkk)))
    (unless di (err/missing-digest dspec))
    (unless (digest-size di) (err/not-fixed-digest di #:in pkk))
    ($pkk-verify (ctx-impl pkk) pkk (digest di inp) dspec pad sig)))

(define (do-sign pkk msg dspec0 pad)
  (define impl (ctx-impl pkk))
  (define dspec (or dspec0 'none))
  (check-sign impl pkk pad dspec)
  (unless (pk-key-private? pkk)
    (crypto-error "signing requires private key" #:in pkk))
  (unless (eq? dspec 'none) (check-sign-msg-size impl msg dspec))
  ($pkk-sign impl pkk msg dspec pad))

(define (do-verify pkk msg dspec0 pad sig)
  (define impl (ctx-impl pkk))
  (define dspec (or dspec0 'none))
  (check-sign impl pkk pad dspec)
  (unless (eq? dspec 'none) (check-sign-msg-size impl msg dspec))
  ($pkk-verify impl pkk msg dspec pad sig))

(define (check-sign impl pad dspec)
  (unless ($pk-can-sign? impl pad dspec)
    (unless ($pk-can-sign? impl #f #f)
      (crypto-error "sign/verify not supported" #:in impl))
    (unless ($pk-can-sign? impl pad #f)
      (crypto-error "sign/verify padding not supported\n  padding: ~e"
                    pad #:in impl))
    (crypto-error "sign/verify digest not supported\n  padding: ~e\n  digest: ~e"
                  pad dspec #:in impl)))

(define (check-sign-msg-size impl msg dspec)
  (check-bytes "digest" msg (digest-spec-size dspec) #:for dspec #:in impl))

;; ----------------------------------------

(define (pk-encrypt pkk buf #:pad [pad #f])
  (with-crypto-entry 'pk-encrypt
    (define impl (ctx-impl pkk))
    (check-encrypt impl pad)
    ($pkk-encrypt impl pkk buf pad)))

(define (pk-decrypt pkk buf #:pad [pad #f])
  (with-crypto-entry 'pk-decrypt
    (define impl (ctx-impl pkk))
    (check-encrypt impl pad)
    (unless (pk-key-private? pkk)
      (crypto-error "decryption requires private key" #:in pkk))
    ($pkk-decrypt impl pkk buf pad)))

(define (check-encrypt impl pad)
  (unless ($pk-can-encrypt? impl pad)
    (unless ($pk-can-encrypt? impl #f)
      (crypto-error "encrypt/decrypt not supported" #:in impl))
    (crypto-error "encrypt/decrypt not supported\n  padding: ~e" #:in impl)))

;; ----------------------------------------

(define (pk-derive-secret pkk peer)
  (with-crypto-entry 'pk-derive-secret
    (define impl (ctx-impl pkk))
    (unless ($pk-can-key-agree? impl)
      (crypto-error "key agreement not supported" #:in impl))
    (let ([peer (convert-peer-key impl pkk peer)])
      ($pkk-compute-secret impl pkk peer))))

(define (convert-peer-key impl pkk peer0)
  (define (incompatible peer)
    (crypto-error "peer key is not compatible\n  peer: ~e" peer #:in pkk))
  (define peer
    (cond [(bytes? peer0) ($pkk-import-for-key-agree impl pkk peer0)]
          [(eq? (ctx-impl peer0) impl) peer0]
          [(pk-import-key impl peer0 #t) => values]
          [else (incompatible peer0)]))
  (unless (and (eq? (ctx-impl peer) impl)
               (eq? ($get-spec peer) ($get-spec impl))
               ($pkk-equal-params? impl pkk peer))
    (incompatible peer))
  peer)

;; ----------------------------------------

(define (generate-private-key pk [config '()])
  (with-crypto-entry 'generate-private-key
    (cond [(pk-parameters? pk)
           (check-config config '() "key generation from parameters" #:in pk)
           ($pkp-generate-key (ctx-impl pk) pk)]
          [else
           (define pki (-get-pk-impl pk))
           ($pk-generate-key pki config)])))

(define (generate-pk-parameters pk [config '()])
  (with-crypto-entry 'generate-pk-parameters
    (define pki (-get-pk-impl pk))
    ($pk-generate-params pki config)))

;; ============================================================
;; Security bits and levels

(define security-strength/c exact-nonnegative-integer?)
(define security-level/c (integer-in 0 5))

;; security-level->strength : Nat[0-5] -> Nat
(define (security-level->strength level)
  (case level [(0) 0] [(1) 80] [(2) 112] [(3) 128] [(4) 192] [(5) 256] [else 256]))

;; security-strength->level : Nat -> Nat[0-5]
(define (security-strength->level secbits)
  (cond [(< secbits 80) 0]
        [(< secbits 112) 1]
        [(< secbits 128) 2]
        [(< secbits 192) 3]
        [(< secbits 256) 4]
        [else 5]))
