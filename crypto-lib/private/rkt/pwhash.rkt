;; Copyright 2018 Ryan Culpepper
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
(require (only-in racket/base [exact-nonnegative-integer? nat?])
         racket/string
         racket/match
         "../common/error.rkt"
         "base64.rkt")
(provide (all-defined-out))

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

;; ------------------------------------------------------------

;; parse : String -> Env/#f
(define (parse s)
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
    [($B64) (b64-decode vstr)]
    [($AB64) (ab64-decode vstr)]))

;; check-param : ValueSpec Env -> Env/#f
(define (check-param pspec env)
  (match pspec
    [($Value sym _ _ _ opt?)
     (cond [(or opt? (hash-has-key? env sym)) env]
           [else #f])]))

;; ------------------------------------------------------------

;; encode : Env -> String
(define (encode env)
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
     (b64-encode/utf-8 v)]
    [($AB64)
     (unless (or (bytes? v) (string? v)) (bad "(or/c bytes? string?)"))
     (ab64-encode/utf-8 v)]))

;; ============================================================
