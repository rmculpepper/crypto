;; Copyright 2014-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/string
         racket/contract/base
         brandx
         base64
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "util.rkt"
         (prefix-in rkt: "../rkt/kdf.rkt"))
(provide (contract-out
          [make-kdf
           (-> kdf-info? factory? (or/c kdf-inner-impl? #f)
               (or/c kdf-impl? #f))]
          [make-kdf-inner-impl
           (->* [(-> kdf-impl? nat? config/c bytes? (or/c bytes? #f) bytes?)]
                [(-> kdf-impl? config/c bytes? (or/c string? #f))
                 (-> kdf-impl? bytes? string? (or/c 'valid 'invalid 'fallback))]
                kdf-inner-impl?)])
         (struct-out common-kdf-impl)
         (struct-out common-kdf-inner-impl)
         hkdf-inner-impl
         ans-x9.63-kdf-inner-impl
         concat-kdf-inner-impl
         sp800-108-counter-hmac-kdf-inner-impl
         sp800-108-feedback-hmac-kdf-inner-impl
         sp800-108-double-pipeline-hmac-kdf-inner-impl
         check-pwhash/kdf-spec
         parse-pwhash
         encode-pwhash
         config:info-kdf
         config:pbkdf2-base
         config:pbkdf2-kdf
         config:scrypt-pwhash
         config:scrypt-kdf
         config:argon2-base
         config:argon2-kdf)

(define (make-kdf info factory inner)
  (and inner (common-kdf-impl info factory inner)))

;; ============================================================
;; KDF and Password Hashing

(struct common-kdf-impl impl-base
  (inner    ;; KDFInnerImpl
   )
  #:properties
  (method-properties
   #:export ([kdf-impl$ #:prefix %]
             [simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs common-kdf-impl)
   (define (%to-write-prefixes self)
     (list* "impl" "kdf" (super-to-write-prefixes self)))

   ;; ---- kdf-info

   (define (%kdf-salt-mode self) ($kdf-salt-mode (.info self)))
   (define (%kdf-salt-default self) ($kdf-salt-default (.info self)))

   ;; ---- kdf-impl

   (define (%kdf-derive self key-size params pass salt)
     (let ([key-size (or key-size (config-ref params 'key-size #f))])
       (unless key-size (crypto-error "missing key-size" #:in self))
       (let ([salt (check-salt self salt)])
         ($kdfi-derive (.inner self) self key-size params pass salt))))

   (define (check-salt self salt)
     (case ($kdf-salt-mode self)
       [(req) (or salt (crypto-error "salt required for KDF" #:in self))]
       [(opt) (or salt ($kdf-salt-default self))]
       [else (if salt (crypto-error "salt not allowed for KDF" #:in self) #f)]))

   (define (%pwhash self config pass)
     (or ($kdfi-pwhash (.inner self) self config pass)
         (fallback-pwhash self config pass)))

   (define (fallback-pwhash self config pass)
     (match ($get-spec self)
       [(or 'argon2id 'argon2i 'argon2d)
        (kdf-pwhash-argon2 self config pass)]
       ['scrypt
        (kdf-pwhash-scrypt self config pass)]
       [(list 'pbkdf2 'hmac dspec)
        (kdf-pwhash-pbkdf2-hmac self dspec config pass)]
       [_ (err/no-impl self)]))

   (define (%pwhash-verify self pass cred)
     (match ($kdfi-pwhash-verify (.inner self) self pass cred)
       ['valid #t]
       ['invalid #f]
       ['fallback (kdf-pwhash-verify self pass cred)]))
   ))

;; ----------------------------------------

(define-interface kdf-inner-impl$
  #:predicate kdf-inner-impl?
  ([kdfi-derive
    (-> kdf-inner-impl? kdf-impl? nat? config/c bytes? (or/c bytes? #f)
        bytes?)]
   [kdfi-pwhash
    (-> kdf-inner-impl? kdf-impl? config/c bytes?
        (or/c string? #f))]
   [kdfi-pwhash-verify
    (-> kdf-inner-impl? kdf-impl? bytes? string?
        (or/c 'valid 'invalid 'fallback))])
  #:generics-prefix $)

(struct common-kdf-inner-impl
  (do-kdf-derive do-pwhash do-verify)
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define-struct-abbrevs common-kdf-inner-impl)
   (define (%kdfi-derive self kdfi key-size config pass salt)
     ((.do-kdf-derive self) kdfi key-size config pass salt))
   (define (%kdfi-pwhash self kdfi config pass)
     ((.do-pwhash self) kdfi config pass))
   (define (%kdfi-pwhash-verify self kdfi config cred)
     ((.do-verify self) kdfi config cred))))

(define (make-kdf-inner-impl do-kdf-derive [do-pwhash #f] [do-verify #f])
  (define (pwhash-none kdfi config pass) #f)
  (define (verify-fallback kdfi config cred) 'fallback)
  (common-kdf-inner-impl do-kdf-derive
                         (or do-pwhash pwhash-none)
                         (or do-verify verify-fallback)))

;; ----------------------------------------

(struct hkdf-inner-impl
  (hmacdi   ;; DigestImpl
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define-struct-abbrevs hkdf-inner-impl)
   (define (%kdfi-derive self kdfi key-size config pass salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define (hmac-h key msg)
       ($digest (.hmacdi self) msg key #f null))
     (rkt:hkdf hmac-h salt info key-size pass))))

(struct ans-x9.63-kdf-inner-impl
  (di       ;; DigestImpl
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define-struct-abbrevs ans-x9.63-kdf-inner-impl)
   (define (%kdfi-derive self kdfi key-size config pass _salt)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define (H msg) ($digest (.di self) msg #f #f null))
     (rkt:ans-x9.63-kdf H info key-size pass))))

(struct concat-kdf-inner-impl
  (hmac?    ;; Boolean
   di       ;; DigestImpl, normal or HMAC
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define (%kdfi-derive self kdfi key-size config pass salt)
     (match-define (concat-kdf-inner-impl hmac? di) self)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define H
       (if hmac?
           (lambda (msg) ($digest di msg salt #f null))
           (lambda (msg) ($digest di msg #f #f null))))
     (rkt:concat-kdf H info key-size pass))))

(struct sp800-108-counter-hmac-kdf-inner-impl
  (di       ;; DigestImpl (HMAC)
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define (%kdfi-derive self kdfi key-size config pass _salt)
     (match-define (sp800-108-counter-hmac-kdf-inner-impl di) self)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define (prf seed msg) ($digest di msg seed #f null))
     (rkt:sp800-108-counter-kdf prf info key-size pass))))

(struct sp800-108-feedback-hmac-kdf-inner-impl
  (di       ;; DigestInfo (HMAC)
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define (%kdfi-derive self kdfi key-size config pass salt)
     (match-define (sp800-108-feedback-hmac-kdf-inner-impl di) self)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define ctr? #t) ;; FIXME, make configurable
     (define (prf seed msg) ($digest di msg seed #f null))
     (rkt:sp800-108-feedback-kdf prf ctr? info key-size salt pass))))

(struct sp800-108-double-pipeline-hmac-kdf-inner-impl
  (di       ;; DigestInfo (HMAC)
   )
  #:properties
  (method-properties
   #:export ([kdf-inner-impl$ #:prefix %])
   (define (%kdfi-derive self kdfi key-size config pass _salt)
     (match-define (sp800-108-double-pipeline-hmac-kdf-inner-impl di) self)
     (define info (check/ref-config '(info) config config:info-kdf #:in kdfi))
     (define ctr? #t) ;; FIXME, make configurable
     (define (prf seed msg) ($digest di msg seed #f null))
     (rkt:sp800-108-double-pipeline-kdf prf ctr? info key-size pass))))


;; ----------------------------------------

(define (kdf-pwhash-argon2 ki config pass)
  (define-values (m t p v)
    (check/ref-config '(m t p v) config config:argon2-base #:in ki))
  (define alg ($get-spec ki))
  (define salt (crypto-random-bytes 16))
  (define pwh ($kdf-derive ki 32 `((m ,m) (t ,t) (p ,p) (v ,v)) pass salt))
  (encode-pwhash (hash '$id alg 'v v 'm m 't t 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-scrypt ki config pass)
  (define-values (ln p r)
    (check/ref-config '(ln p r) config config:scrypt-pwhash #:in ki))
  (define salt (crypto-random-bytes 16))
  (define pwh ($kdf-derive ki 32 `((N ,(expt 2 ln)) (r ,r) (p ,p)) pass salt))
  (encode-pwhash (hash '$id 'scrypt 'ln ln 'r r 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-pbkdf2-hmac ki dspec config pass)
  (define id
    (case dspec
      [(sha1) 'pbkdf2]
      [(sha256) 'pbkdf2-sha256]
      [(sha512) 'pbkdf2-sha512]
      [else (crypto-error "PBKDF2 variant unsupported for password hashing" #:in ki)]))
  (define-values (iters)
    (check/ref-config '(iterations) config config:pbkdf2-base #:in ki))
  (define salt (crypto-random-bytes 16))
  (define pwh ($kdf-derive ki 32 `((iterations ,iters)) pass salt))
  (encode-pwhash (hash '$id id 'rounds iters 'salt salt 'pwhash pwh)))

(define (check-pwhash/kdf-spec cred spec)
  (define id (peek-id cred))
  (unless (equal? spec (id->kdf-spec id))
    (crypto-error "KDF implementation does not match given password hash algorithm\n  given: ~a"
                  (format "$~.a$ password hash" id))))

(define (kdf-pwhash-verify ki pass cred)
  (check-pwhash/kdf-spec cred ($get-spec ki))
  (define env (parse-pwhash cred))
  (define config
    (match env
      [(hash-table ['$id (or 'argon2i 'argon2d 'argon2id)] ['v v] ['m m] ['t t] ['p p])
       `((v ,v) (m ,m) (t ,t) (p ,p))]
      [(hash-table ['$id (or 'pbkdf2 'pbkdf2-sha256 'pbkdf2-sha512)] ['rounds rounds])
       `((iterations ,rounds))]
      [(hash-table ['$id 'scrypt] ['ln ln] ['r r] ['p p])
       `((N ,(expt 2 ln)) (r ,r) (p ,p))]))
  (define salt (hash-ref env 'salt))
  (define pwh (hash-ref env 'pwhash))
  (define pwh* ($kdf-derive ki (bytes-length pwh) config pass salt))
  (crypto-bytes=? pwh pwh*))

(define (id->kdf-spec id)
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2)        '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [else #f]))

;; ----------------------------------------

;; Deprecated:
(define config:kdf-key-size
  `((key-size   ,exact-positive-integer? #f #:opt 32)))

(define config:info-kdf
  `((info       ,bytes?                  #f #:opt #"")
    ,@config:kdf-key-size))

(define config:pbkdf2-base
  `((iterations ,exact-positive-integer? #f #:req)))

(define config:pbkdf2-kdf
  `(,@config:kdf-key-size
    ,@config:pbkdf2-base))

(define config:scrypt-pwhash
  `((ln ,exact-positive-integer? #f #:req)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:scrypt-kdf
  `(,@config:kdf-key-size
    (N  ,exact-positive-integer? #f #:alt ln)
    (ln ,exact-positive-integer? #f #:alt N)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:argon2-base
  `((t ,exact-positive-integer? #f #:req)
    (m ,exact-positive-integer? #f #:req)
    (p ,exact-positive-integer? #f #:opt 1)
    (v ,(lambda (v) (member v '(16 19))) "(or/c 16 19)" #:opt 19)))

(define config:argon2-kdf
  `(,@config:kdf-key-size
    ,@config:argon2-base))

;; ============================================================
;; Password Hash format codec

;; References:
;; - https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
;; - https://passlib.readthedocs.io/en/stable/modular_crypt_format.html
;; - https://www.akkadia.org/drepper/SHA-crypt.txt

;; peek-id : String -> Symbol/#f
(define (peek-id s)
  (cond [(regexp-match #rx"^[$]([a-z0-9-]*)[$]" s)
         => (lambda (m) (string->symbol (cadr m)))]
        [else #f]))

;; id->crypt-spec : Symbol -> CryptSpec
(define (id->crypt-spec id)
  (let ([10^6-1 (sub1 (expt 10 6))]
        [2^32-1 (sub1 (expt 2 32))])
    (case id
      [(argon2i argon2d argon2id)
       (CS ($Maybe (P (V 'v Nat)))
           (P (V 'm ($Nat 1 2^32-1)) (V 't ($Nat 1 2^32-1)) (V 'p ($Nat 1 255)))
           (V 'salt B64)
           (V 'pwhash B64))]
      [(scrypt)
       (CS (P (V 'ln Nat) (V 'r Nat) (V 'p Nat))
           (V 'salt B64) ;; ?? or Raw?
           (V 'pwhash B64))]
      [(pbkdf2 pbkdf2-sha1 pbkdf2-sha256 pbkdf2-sha512)
       (CS (V 'rounds ($Nat 1 2^32-1))
           (V 'salt AB64)
           (V 'pwhash AB64))]
      [(scram)
       (CS (V 'rounds ($Nat 1 2^32-1))
           (V 'salt AB64)
           ;; FIXME: support for sha1, sha256, and sha512 hardcoded
           (P (V 'sha-1   AB64 #:opt #t)
              (V 'sha-256 AB64 #:opt #t)
              (V 'sha-512 AB64 #:opt #t)))]
      [(bcrypt 2b)
       (CS (V 'rounds Nat)
           ($Cat 22 (V 'salt Raw) (V 'pwhash Raw)))]
      [(|5| sha256-crypt |6| sha512-crypt)
       (CS (P (V 'rounds ($Nat 1000 10^6-1)))
           (V 'salt Raw)
           (V 'pwhash Raw))]
      [else (crypto-error "unsupported algorithm\n  algorithm: ~e" id)])))

;; ============================================================

;; A CryptSpec is (listof CryptSpecElem)

;; A CryptSpecElem is one of:
(struct $Maybe (cse) #:prefab)
(struct $Params (vs) #:prefab)
(struct $Value (sym vspec lb ub default) #:prefab)
(struct $Cat (len cse1 cse2) #:prefab)
(define (CS . args) args)
(define (P . args) ($Params args))
(define (V name vspec [lb 0] [ub +inf.0] #:opt [optional? #f])
  ($Value name vspec lb ub optional?))

;; A ValueSpec is one of:
(struct $Raw () #:prefab)
(struct $Nat (nlb nub) #:prefab)
(struct $B64 () #:prefab)
(struct $AB64 () #:prefab)
(define Nat ($Nat 0 +inf.0))
(define Raw ($Raw))
(define B64 ($B64))
(define AB64 ($AB64))

;; ------------------------------------------------------------

;; parse-pwhash : String -> Env/#f
(define (parse-pwhash s)
  (define id (peek-id s))
  (cond [(id->crypt-spec id) => (lambda (cs) (parse-cs cs s (hash '$id id)))]
        [else #f]))

;; parse-cs : CryptSpec String Env -> Env/#f
(define (parse-cs cs s env)
  (define parts (string-split s #rx"[$]" #:trim? #f #:repeat? #f))
  (match parts
    [(list* "" _ parts)
     (let loop ([cses cs] [parts parts] [env env])
       (match cses
         [(cons ($Maybe cse) cses)
          (match parts
            [(cons part parts)
             (or (let ([env (parse-cse cse part env)]) (and env (loop cses parts env)))
                 (loop cses (cons part parts) env))]
            ['() (loop cses parts env)])]
         [(cons cse cses)
          (match parts
            [(cons part parts)
             (let ([env (parse-cse cse part env)])
               (and env (loop cses parts env)))]
            [_ #f])]
         ['() (match parts ['() env] [_ #f])]))]
    [_ #f]))

;; parse-cse : CryptSpecElem String Env -> Env/#f
(define (parse-cse cse s env)
  (match cse
    [($Params pspecs)
     (define parts (string-split s #rx"[,]" #:trim? #f #:repeat? #f))
     (define env*
       (for/fold ([env env]) ([part (in-list parts)])
         (and env (parse-param pspecs part env))))
     (for/fold ([env env*]) ([pspec (in-list pspecs)])
       (and env (check-param pspec env)))]
    [($Value sym vspec lb ub _)
     (and (<= lb (string-length s) ub)
          (let ([v (convert-value s vspec)])
            (and v (hash-set env sym v))))]
    [($Cat len cse1 cse2)
     (and (>= (string-length s) len)
          (let ([env (parse-cse cse1 (substring s 0 len) env)])
            (and env (parse-cse cse2 (substring s len) env))))]))

;; parse-param : ParamSpec String Env -> Env/#f
(define (parse-param ps param env)
  (cond [(regexp-match #rx"^([a-z0-9-]*)=([a-zA-Z0-9/+.-]*)$" param)
         => (match-lambda
              [(list _ key-str value-str)
               (define key (string->symbol key-str))
               (cond [(lookup-param-vspec key ps)
                      => (lambda (vspec)
                           (let ([value (convert-value value-str vspec)])
                             (and value (hash-set env key value))))]
                     [else #f])])]
        [else #f]))

;; lookup-param-vspec : Symbol (Listof $Value) -> ValueSpec
(define (lookup-param-vspec sym pspecs)
  (for/or ([pspec (in-list pspecs)] #:when (eq? sym ($Value-sym pspec)))
    ($Value-vspec pspec)))

;; convert-value : String ValueSpec -> Any
(define (convert-value vstr vspec)
  (match vspec
    [($Raw) (string->bytes/utf-8 vstr)]
    [($Nat lb ub)
     (define n (string->number vstr))
     (and (exact-nonnegative-integer? n)
          (<= lb n ub)
          n)]
    [($B64) (base64-decode vstr #:mode 'strict)]
    [($AB64) (base64-decode vstr #:endcodes #"./" #:mode 'strict)]))

;; check-param : ValueSpec Env -> Env/#f
(define (check-param pspec env)
  (match pspec
    [($Value sym _ _ _ opt?)
     (cond [(or opt? (hash-has-key? env sym)) env]
           [else #f])]))

;; ------------------------------------------------------------

;; encode-pwhash : Env -> String
(define (encode-pwhash env)
  (define id (hash-ref env '$id))
  (define cses (id->crypt-spec id))
  (let ([parts (map (lambda (cse) (encode-cse cse env)) cses)])
    (format "$~a$~a" id (string-join (filter values parts) "$"))))

;; encode-cse : CryptSpecElem Env -> String/#f
(define (encode-cse cse env)
  (match cse
    [($Maybe cse)
     (with-handlers ([exn:fail? (lambda (e) #f)])
       (encode-cse cse env))]
    [($Params pspecs)
     (define parts (filter values (map (lambda (p) (encode-param p env)) pspecs)))
     (string-join parts ",")]
    [($Value sym vspec _ _ _)
     (encode-value (hash-ref env sym) vspec)]
    [($Cat len cse1 cse2)
     (let ([s1 (encode-cse cse1 env)])
       (unless (= (string-length s1) len)
         (error 'encode-cse "bad length"))
       (string-append s1 (encode-cse cse2 env)))]))

;; encode-param : $Value Env -> String/#f
(define (encode-param pspec env)
  (match pspec
    [($Value sym vspec _ _ opt?)
     (cond [(hash-ref env sym #f)
            => (lambda (v) (format "~a=~a" sym (encode-value v vspec)))]
           [opt? #f]
           [else (error 'encode-param "missing parameter: ~e" sym)])]))

;; enode-value : Any ValueSpec -> String
(define (encode-value v vspec)
  (define (bad want)
    (error 'encode-value "bad value\n  expected: ~a\n  given: ~e" want v))
  (match vspec
    [($Raw) (unless (bytes? v) (bad "bytes?")) (bytes->string/utf-8 v)]
    [($Nat lb ub)
     (unless (and (nat? v) (<= lb v ub)) (bad "integer"))
     (number->string v)]
    [($B64)
     (unless (or (bytes? v) (string? v)) (bad "(or/c bytes? string?)"))
     (bytes->string/utf-8
      (base64-encode v #:line #f #:pad? #f))]
    [($AB64)
     (unless (or (bytes? v) (string? v)) (bad "(or/c bytes? string?)"))
     (bytes->string/utf-8
      (base64-encode v #:endcodes #"./" #:line #f #:pad? #f))]))
