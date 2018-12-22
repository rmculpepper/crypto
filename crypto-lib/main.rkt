;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require racket/contract/base
         racket/class
         racket/random
         "private/common/interfaces.rkt"
         "private/common/catalog.rkt"
         "private/common/common.rkt"
         "private/common/error.rkt"
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
;; Factories

;; Copyright 2013-2018 Ryan Culpepper

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

(define (get-factory i)
  (with-crypto-entry 'get-factory
    (let loop ([i i])
      (cond [(is-a? i impl<%>) (send i get-factory)]
            [(is-a? i ctx<%>) (loop (send i get-impl))]))))

(define (get-digest di [factory/s (crypto-factories)])
  (with-crypto-entry 'get-digest
    (for/or ([f (in-list (coerce-list factory/s))])
      (send f get-digest di))))

(define (get-cipher ci [factory/s (crypto-factories)])
  (with-crypto-entry 'get-cipher
    (for/or ([f (in-list (coerce-list factory/s))])
      (send f get-cipher ci))))

(define (get-pk pki [factory/s (crypto-factories)])
  (with-crypto-entry 'get-pk
    (for/or ([f (in-list (coerce-list factory/s))])
      (send f get-pk pki))))

(define (get-kdf k [factory/s (crypto-factories)])
  (with-crypto-entry 'get-kdf
    (for/or ([f (in-list (coerce-list factory/s))])
      (send f get-kdf k))))

(define (factory-print-info factory)
  (send factory print-info) (void))

(define (factory-version factory)
  (send factory get-version))


;; ============================================================
;; Digests

;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>

(provide
 (contract-out
  [digest-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) exact-nonnegative-integer?)]
  [digest-block-size
   (-> (or/c digest-spec? digest-impl? digest-ctx?) exact-nonnegative-integer?)]
  [digest
   (->* [digest/c input/c] [#:key (or/c bytes? #f)] bytes?)]
  [hmac
   (-> digest/c bytes? input/c bytes?)]
  [make-digest-ctx
   (->* [digest/c] [#:key (or/c bytes? #f)] digest-ctx?)]
  [digest-update
   (-> digest-ctx? input/c void?)]
  [digest-final
   (-> digest-ctx? bytes?)]
  [digest-copy
   (-> digest-ctx? (or/c digest-ctx? #f))]
  [digest-peek-final
   (-> digest-ctx? (or/c bytes? #f))]
  [make-hmac-ctx
   (-> digest/c bytes? digest-ctx?)]
  [generate-hmac-key
   (-> digest/c bytes?)]))

(define digest/c (or/c digest-spec? digest-impl?))
(define (-get-digest-impl o) (to-impl o #:what "digest" #:lookup get-digest))
(define (-get-digest-info o) (to-info o #:what "digest" #:lookup digest-spec->info))

;; ----

(define (digest-size o)
  (with-crypto-entry 'digest-size
    (send (-get-digest-info o) get-size)))
(define (digest-block-size o)
  (with-crypto-entry 'digest-block-size
    (send (-get-digest-info o) get-block-size)))

;; ----

(define (make-digest-ctx di #:key [key #f])
  (with-crypto-entry 'make-digest-ctx
    (send (-get-digest-impl di) new-ctx key)))

(define (digest-update dg src)
  (with-crypto-entry 'digest-update
    (send dg update src)))

(define (digest-final dg)
  (with-crypto-entry 'digest-final
    (send dg final)))

(define (digest-copy dg)
  (with-crypto-entry 'digest-copy
    (send dg copy)))

(define (digest-peek-final dg)
  (with-crypto-entry 'digest-peek-final
    (let ([dg2 (send dg copy)]) (and dg2 (send dg2 final)))))

;; ----

(define (digest di inp #:key [key #f])
  (with-crypto-entry 'digest
    (let ([di (-get-digest-impl di)])
      (send di digest inp key))))

;; ----

(define (make-hmac-ctx di key)
  (with-crypto-entry 'make-hmac-ctx
    (let ([di (-get-digest-impl di)])
      (send di new-hmac-ctx key))))

(define (hmac di key inp)
  (with-crypto-entry 'hmac
    (let ([di (-get-digest-impl di)])
      (send di hmac key inp))))

;; ----

(define (generate-hmac-key di)
  (with-crypto-entry 'generate-hmac-key
    (crypto-random-bytes (digest-size di))))

;; ============================================================
;; Ciphers

;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>

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

(define (-get-cipher-impl o) (to-impl o #:what "cipher" #:lookup get-cipher))
(define (-get-cipher-info o) (to-info o #:what "cipher" #:lookup cipher-spec->info))

;; ----

;; Defer to impl when avail to support unknown ciphers or impl-dependent limits.

(define (cipher-default-key-size o)
  (with-crypto-entry 'cipher-default-key-size
    (send (-get-cipher-info o) get-key-size)))
(define (cipher-key-sizes o)
  (with-crypto-entry 'cipher-key-sizes
    (size-set->list (send (-get-cipher-info o) get-key-sizes))))
(define (cipher-block-size o)
  (with-crypto-entry 'cipher-block-size
    (send (-get-cipher-info o) get-block-size)))
(define (cipher-chunk-size o)
  (with-crypto-entry 'cipher-chunk-size
    (send (-get-cipher-info o) get-chunk-size)))
(define (cipher-iv-size o)
  (with-crypto-entry 'cipher-iv-size
    (send (-get-cipher-info o) get-iv-size)))
(define (cipher-aead? o)
  (with-crypto-entry 'cipher-aead?
    (send (-get-cipher-info o) aead?)))
(define (cipher-default-auth-size o)
  (with-crypto-entry 'cipher-default-auth-size
    (send (-get-cipher-info o) get-auth-size)))

;; ----

(define (encrypt-ctx? x)
  (and (cipher-ctx? x) (send x get-encrypt?)))
(define (decrypt-ctx? x)
  (and (cipher-ctx? x) (not (send x get-encrypt?))))

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
    (send ci new-ctx key (or iv #"") #t pad auth-size auth-attached?)))
(define (-decrypt-ctx ci key iv pad auth-size auth-attached?)
  (let ([ci (-get-cipher-impl ci)])
    (send ci new-ctx key (or iv #"") #f pad auth-size auth-attached?)))

(define (cipher-update-aad c inp)
  (with-crypto-entry 'cipher-update-aad
    (send c update-aad inp)
    (void)))

(define (cipher-update c inp)
  (with-crypto-entry 'cipher-update
    (send c update inp)
    (send c get-output)))

(define (cipher-final c [auth-tag #f])
  (with-crypto-entry 'cipher-final
    (send c final auth-tag)
    (send c get-output)))

(define (cipher-get-auth-tag c)
  (with-crypto-entry 'cipher-get-auth-tag
    (send c get-auth-tag)))

;; ----

(define (encrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt
    (let ([ci (-get-cipher-impl ci)])
      (define ctx (-encrypt-ctx ci key iv pad auth-size #t))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (send ctx get-output))))

(define (decrypt ci key iv inp
                 #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-cipher-impl ci)])
      (define ctx (-decrypt-ctx ci key iv pad auth-size #t))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (send ctx get-output))))

(define (encrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-size [auth-size #f])
  (with-crypto-entry 'encrypt/auth
    (let ([ci (-get-cipher-impl ci)])
      (define ctx (-encrypt-ctx ci key iv pad auth-size #f))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final #f)
      (values (send ctx get-output) (send ctx get-auth-tag)))))

(define (decrypt/auth ci key iv inp
                      #:pad [pad default-pad] #:aad [aad-inp null] #:auth-tag [auth-tag #f])
  (with-crypto-entry 'decrypt
    (let ([ci (-get-cipher-impl ci)])
      (define auth-len (and auth-tag (bytes-length auth-tag)))
      (define ctx (-decrypt-ctx ci key iv pad auth-len #f))
      (send ctx update-aad aad-inp)
      (send ctx update inp)
      (send ctx final auth-tag)
      (send ctx get-output))))

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

;; Copyright 2014-2018 Ryan Culpepper

(provide
 (contract-out
  [kdf
   (->* [(or/c kdf-spec? kdf-impl?)
         bytes?
         (or/c bytes? #f)]
        [(listof (list/c symbol? any/c))]
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
        [#:p exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  ))

(define (-get-kdf-impl o) (to-impl o #:what "KDF" #:lookup get-kdf))

(define (kdf k pass salt [params '()])
  (with-crypto-entry 'kdf
    (let ([k (-get-kdf-impl k)])
      (send k kdf0 params pass salt))))

(define (pwhash k pass [params '()])
  (with-crypto-entry 'pwhash
    (let ([k (-get-kdf-impl k)])
      (send k pwhash params pass))))

(define (pwhash-verify k pass cred)
  (with-crypto-entry 'pwhash-verify
    (define k* (or k (-get-kdf-impl (pwcred->kdf-spec cred))))
    (send k* pwhash-verify pass cred)))

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
      (send k kdf `((iterations ,iterations) (key-size ,key-size)) pass salt))))

(define (scrypt pass salt
                #:N N
                #:p [p 1]
                #:r [r 8]
                #:key-size [key-size 32])
  (with-crypto-entry 'scrypt
    (let ([k (-get-kdf-impl 'scrypt)])
      (send k kdf `((N ,N) (p ,p) (r ,r) (key-size ,key-size))
            pass salt))))

;; ============================================================
;; Public-key Systems

;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>

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

  [pk-key->parameters
   (-> pk-key? (or/c pk-parameters? #f))]

  [public-key=?
   (->* [pk-key?] [] #:rest (listof pk-key?) boolean?)]
  [pk-key->public-only-key
   (-> pk-key? public-only-key?)]

  [pk-key->datum
   (-> pk-key? symbol? any/c)]
  [datum->pk-key
   (->* [any/c symbol?] [(or/c crypto-factory? (listof crypto-factory?))]
        pk-key?)]

  [pk-parameters->datum
   (-> pk-parameters? symbol? any/c)]
  [datum->pk-parameters
   (->* [any/c symbol?] [(or/c crypto-factory? (listof crypto-factory?))]
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

(define (-get-impl pki) (to-impl pki #:what "algorithm" #:lookup get-pk))

;; ----------------------------------------

;; A private key is really a keypair, including both private and public parts.
;; A public key contains only the public part.
(define (private-key? x)
  (and (is-a? x pk-key<%>) (send x is-private?)))
(define (public-only-key? x)
  (and (is-a? x pk-key<%>) (not (send x is-private?))))

(define (pk-can-sign? pki [pad #f] [dspec #f])
  (with-crypto-entry 'pk-can-sign?
    (cond [(pk-spec? pki) (pk-spec-can-sign? pki pad)] ;; no dspec!
          [else (let ([impl (to-impl pki)])
                  (case (send impl can-sign? pad)
                    [(depends) (and (send impl can-sign2? pad dspec) #t)]
                    [(nodigest) (and (memq dspec '(#f none)) #t)]
                    [(#f) #f]
                    [else #t]))])))
(define (pk-can-encrypt? pki [pad #f])
  (with-crypto-entry 'pk-can-encrypt?
    (cond [(pk-spec? pki) (pk-spec-can-encrypt? pki)]
          [else (and (send (to-impl pki) can-encrypt? pad) #t)])))
(define (pk-can-key-agree? pki)
  (with-crypto-entry 'pk-can-key-agree?
    (cond [(pk-spec? pki) (pk-spec-can-key-agree? pki)]
          [else (and (send (to-impl pki) can-key-agree?) #t)])))
(define (pk-has-parameters? pki)
  (with-crypto-entry 'pk-has-parameters?
    (cond [(pk-spec? pki) (pk-spec-has-parameters? pki)]
          [else (and (send (to-impl pki) has-params?) #t)])))

(define (pk-key->parameters pk)
  (with-crypto-entry 'pk-key->parameters
    (and (pk-has-parameters? pk)
         (send pk get-params))))

;; Are the *public parts* of the given keys equal?
(define (public-key=? k1 . ks)
  (with-crypto-entry 'public-key=?
    (for/and ([k (in-list ks)])
      (send k1 equal-to-key? k))))

(define (pk-key->datum pk fmt)
  (with-crypto-entry 'pk-key->datum
    (send pk write-key fmt)))
(define (datum->pk-key datum fmt [factory/s (crypto-factories)])
  (with-crypto-entry 'datum->pk-key
    (or (for/or ([factory (in-list (if (list? factory/s) factory/s (list factory/s)))])
          (let ([reader (send factory get-pk-reader)])
            (and reader (send reader read-key datum fmt))))
        (crypto-error "unable to read key\n  format: ~e" fmt))))

(define (pk-parameters->datum pkp fmt)
  (with-crypto-entry 'pk-parameters->datum
    (send pkp write-params fmt)))
(define (datum->pk-parameters datum fmt [factory/s (crypto-factories)])
  (with-crypto-entry 'datum->pk-parameters
    (or (for/or ([factory (in-list (if (list? factory/s) factory/s (list factory/s)))])
          (let ([reader (send factory get-pk-reader)])
            (and reader (send reader read-params datum fmt))))
        (crypto-error "unable to read parameters\n  format: ~e" fmt))))

(define (pk-key->public-only-key pk)
  (with-crypto-entry 'pk-key->public-only-key
    (send pk get-public-key)))

;; ----------------------------------------

(define (pk-sign pk msg #:digest [dspec #f] #:pad [pad #f])
  (with-crypto-entry 'pk-sign
    (send pk sign msg dspec pad)))

(define (pk-verify pk msg sig #:digest [dspec #f] #:pad [pad #f])
  (with-crypto-entry 'pk-verify
    (send pk verify msg dspec pad sig)))

(define (pk-sign-digest pk di dbuf #:pad [pad #f])
  (with-crypto-entry 'pk-sign-digest
    (let ([di (to-spec di)])
      (send pk sign dbuf di pad))))
(define (pk-verify-digest pk di dbuf sig #:pad [pad #f])
  (with-crypto-entry 'pk-verify-digest
    (let ([di (to-spec di)])
      (send pk verify dbuf di pad sig))))

(define (digest/sign pk di inp #:pad [pad #f])
  (with-crypto-entry 'digest/sign
    (let* ([di (to-spec di)]
           [di* (get-digest di (get-factory pk))])
      (send pk sign (digest di* inp) di pad))))

(define (digest/verify pk di inp sig #:pad [pad #f])
  (with-crypto-entry 'digest/verify
    (let* ([di (to-spec di)]
           [di* (get-digest di (get-factory pk))])
      (send pk verify (digest di* inp) di pad sig))))

;; ----------------------------------------

(define (pk-encrypt pk buf #:pad [pad #f])
  (with-crypto-entry 'pk-encrypt
    (send pk encrypt buf pad)))

(define (pk-decrypt pk buf #:pad [pad #f])
  (with-crypto-entry 'pk-decrypt
    (send pk decrypt buf pad)))

;; ----------------------------------------

(define (pk-derive-secret pk peer-key)
  (with-crypto-entry 'pk-derive-secret
    (send pk compute-secret peer-key)))

;; ----------------------------------------

(define (generate-private-key pki [config '()])
  (with-crypto-entry 'generate-private-key
    (if (is-a? pki pk-params<%>)
        (send pki generate-key config)
        (let ([pki (-get-impl pki)])
          (send pki generate-key config)))))

(define (generate-pk-parameters pki [config '()])
  (with-crypto-entry 'generate-pk-parameters
    (let ([pki (-get-impl pki)])
      (send pki generate-params config))))
