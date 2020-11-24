;; Copyright 2014-2018 Ryan Culpepper
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
(require racket/class
         racket/match
         racket/string
         base64
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "util.rkt"
         (prefix-in rkt: "../rkt/kdf.rkt"))
(provide kdf-impl-base%
         hkdf-impl%
         ans-x9.63-kdf-impl%
         concat-kdf-impl%
         sp800-108-counter-hmac-kdf-impl%
         sp800-108-feedback-hmac-kdf-impl%
         sp800-108-double-pipeline-hmac-kdf-impl%
         kdf-pwhash-argon2
         kdf-pwhash-scrypt
         kdf-pwhash-pbkdf2
         kdf-pwhash-verify
         check-pwhash/kdf-spec
         parse-pwhash
         encode-pwhash
         config:pbkdf2-base
         config:pbkdf2-kdf
         config:scrypt-pwhash
         config:scrypt-kdf
         config:argon2-base
         config:argon2-kdf)

;; ============================================================
;; KDF and Password Hashing

(define kdf-impl-base%
  (class* impl-base% (kdf-impl<%>)
    (inherit about)
    (super-new)
    (define/public (kdf0 params pass salt)
      (kdf params pass (check-salt salt)))
    (define/public (kdf params pass salt)
      (err/no-impl this))
    (define/public (pwhash params pass)
      (err/no-impl this))
    (define/public (pwhash-verify pass cred)
      (err/no-impl this))
    (define/public (salt-allowed?) #t)
    (define/public (check-salt salt)
      (unless salt (crypto-error "salt required for KDF\n  KDF: ~a" (about)))
      salt)
    ))

(define kdf-impl-base/no-salt%
  (class kdf-impl-base%
    (inherit about)
    (super-new)
    (define/override (salt-allowed?) #f)
    (define/override (check-salt salt)
      (when salt (crypto-error "salt not allowed for KDF\n  KDF: ~a" (about)))
      #f)
    ))

(define hkdf-impl%
  (class kdf-impl-base%
    (init-field di)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf "HKDF"))
      (define salt* (or salt (make-bytes (send di get-block-size) 0)))
      (define (hmac-h key msg) (send di hmac key msg))
      (rkt:hkdf hmac-h salt* info key-size pass))

    (define/override (check-salt salt)
      (or salt (make-bytes (send di get-block-size) 0)))
    ))

(define ans-x9.63-kdf-impl%
  (class kdf-impl-base/no-salt%
    (init-field di)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf "ANS X9.63 KDF"))
      (define (H msg) (send di digest msg #f))
      (rkt:ans-x9.63-kdf H info key-size pass))
    ))

(define concat-kdf-impl%
  (class kdf-impl-base%
    (inherit about)
    (init-field di hmac?)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf
                          "NIST SP 800-56 One-Step KDF"))
      (define salt*
        (cond [(and hmac? salt) salt]
              [hmac? (make-bytes (send di get-block-size) 0)]
              [salt (crypto-error "salt not supported for KDF\n  KDF: ~a" (about))]
              [else #f]))
      (define H
        (cond [hmac? (lambda (msg) (send di hmac salt* msg))]
              [else  (lambda (msg) (send di digest msg #f))]))
      (rkt:concat-kdf H info key-size pass))

    (define/override (salt-allowed?) hmac?)
    (define/override (check-salt salt) salt)
    ))

(define sp800-108-counter-hmac-kdf-impl%
  (class kdf-impl-base/no-salt%
    (init-field di)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf
                          "NIST SP 800-108 Counter KDF"))
      (define (prf seed msg) (send di hmac seed msg))
      (rkt:sp800-108-counter-kdf prf info key-size pass))
    ))

(define sp800-108-feedback-hmac-kdf-impl%
  (class kdf-impl-base%
    (inherit about)
    (init-field di)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf
                          "NIST SP 800-108 Feedback KDF"))
      (define ctr? #t) ;; FIXME, make configurable
      (define (prf seed msg) (send di hmac seed msg))
      (rkt:sp800-108-feedback-kdf prf ctr? info key-size salt pass))

    (define/override (check-salt salt) (or salt #""))
    ))

(define sp800-108-double-pipeline-hmac-kdf-impl%
  (class kdf-impl-base/no-salt%
    (init-field di)
    (super-new)

    (define/override (kdf params pass salt)
      (define-values (info key-size)
        (check/ref-config '(info key-size) params config:info-kdf
                          "NIST SP 800-108 Double-Pipeline KDF"))
      (define ctr? #t) ;; FIXME, make configurable
      (define (prf seed msg) (send di hmac seed msg))
      (rkt:sp800-108-double-pipeline-kdf prf ctr? info key-size pass))
    ))


;; ----------------------------------------

(define (kdf-pwhash-argon2 ki config pass)
  (define-values (m t p)
    (check/ref-config '(m t p) config config:argon2-base "argon2"))
  (define alg (send ki get-spec))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((m ,m) (t ,t) (p ,p) (key-size 32)) pass salt))
  (encode-pwhash (hash '$id alg 'm m 't t 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-scrypt ki config pass)
  (define-values (ln p r)
    (check/ref-config '(ln p r) config config:scrypt-pwhash "scrypt"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32)) pass salt))
  (encode-pwhash (hash '$id 'scrypt 'ln ln 'r r 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-pbkdf2 ki spec config pass)
  (define id (or (hash-ref pbkdf2-spec=>id spec #f)
                 (crypto-error "unsupported spec")))
  (define-values (iters)
    (check/ref-config '(iterations) config config:pbkdf2-base "PBKDF2"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((iterations ,iters) (key-size 32)) pass salt))
  (encode-pwhash (hash '$id id 'rounds iters 'salt salt 'pwhash pwh)))

(define pbkdf2-spec=>id
  (hash '(pbkdf2 hmac sha1)   'pbkdf2
        '(pbkdf2 hmac sha256) 'pbkdf2-sha256
        '(pbkdf2 hmac sha512) 'pbkdf2-sha512))

(define (check-pwhash/kdf-spec cred spec)
  (define id (peek-id cred))
  (unless (equal? spec (id->kdf-spec id))
    (crypto-error "KDF algorithm does not match given password hash algorithm\n  given: ~a"
                  (format "$~.a$ password hash" id))))

(define (kdf-pwhash-verify ki pass cred)
  (check-pwhash/kdf-spec cred (send ki get-spec))
  (define env (parse-pwhash cred))
  (define config
    (match env
      [(hash-table ['$id (or 'argon2i 'argon2d 'argon2id)] ['m m] ['t t] ['p p])
       `((m ,m) (t ,t) (p ,p) (key-size 32))]
      [(hash-table ['$id (or 'pbkdf2 'pbkdf2-sha256 'pbkdf2-sha512)] ['rounds rounds])
       `((iterations ,rounds) (key-size 32))]
      [(hash-table ['$id 'scrypt] ['ln ln] ['r r] ['p p])
       `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32))]))
  (define salt (hash-ref env 'salt))
  (define pwh (hash-ref env 'pwhash))
  (define pwh* (send ki kdf config pass salt))
  (crypto-bytes=? pwh pwh*))

(define (id->kdf-spec id)
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2)        '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [else #f]))

;; ----------------------------------------

;; FIXME: make key-size a param to kdf instead?
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
    (p ,exact-positive-integer? #f #:opt 1)))

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
       (CS ($Maybe (P (V 'v Raw)))
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

(define nat? exact-nonnegative-integer?)

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

;; encode : Env -> String
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
