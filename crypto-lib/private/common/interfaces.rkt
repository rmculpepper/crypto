;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/contract/base
         brandx
         "catalog.rkt"
         "error.rkt")
(provide (all-from-out "catalog.rkt")
         (all-defined-out)
         (struct-out bytes-range))

;; ============================================================
;; General Notes

;; All sizes are expressed as a number of bytes unless otherwise noted.
;; eg, (send a-sha1-impl get-size) => 20

;; Whenever a string S is accepted as an input, it is interpreted as
;; equivalent to (string->bytes/utf-8 S).

;; ============================================================

(define (crypto-factory? x) (factory? x))
(define (impl? x) (impl-base? x))
(define (info? x) (info-base? x))

;; ============================================================

;; impl-base: Base struct for all "implementation" types.
(struct impl-base (info factory)
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   (define-struct-abbrevs impl-base)
   ;; ----
   (define (%to-write-string self)
     (format "~s" ($get-spec self)))
   (define (%to-write-prefixes self)
     (list ($factory-name (.factory self))))))

;; ctx: Base struct for all "context" types: digest-ctx, cipher-ctx,
;; pk-key, pk-parameters. The inner field stores an "inner context"
;; (ic) with an impl-specific type.

;; General invariant for impl interfaces below taking impl (self) and
;; context argument: impl field of context matches impl.

(struct ctx (impl [inner #:mutable])
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   (define-struct-abbrevs ctx)
   ;; ----
   (define (%to-write-string self)
     ($to-write-string (.impl self)))
   (define (%to-write-prefixes self)
     (cons "ctx" (cdr ($to-write-prefixes (.impl self)))))))

;; ----------------------------------------

(define ($get-spec v)
  (info-base-spec ($get-info v)))

(define ($get-info v)
  (match v
    [(? info-base? v) v]
    [(impl-base info _) info]
    [(ctx (impl-base info _) _) info]))

(define ($get-factory v)
  (match v
    [(impl-base _ factory) factory]
    [(ctx (impl-base _ factory) _) factory]))

;; ============================================================

(struct state-ctx ctx (lock))
(struct statelock (sema [state #:mutable] desc))

(define (call-with-state stctx proc
                         #:ok   [ok-states #f]
                         #:pre  [pre-state #f]
                         #:post [post-state #f]
                         #:msg  [msg #f])
  (define self (state-ctx-lock stctx))
  (define-struct-abbrevs statelock)
  (define (set-state new-state)
    (unless (equal? (.state self) new-state)
      (.state-set! self new-state)))
  (define (bad-state state ok-states msg)
    (crypto-error "wrong state\n  state: ~a~a"
                  (describe-state state)
                  (or msg "")))
  (define (describe-state state)
    (cond [(.desc self)
           (cond [(assoc state (.desc self))
                  => cadr]
                 [else (format "unknown (~s)" state)])]
          [else (format "~s" state)]))
  (call-with-semaphore (.sema self)
    (lambda ()
      (define now-state (.state self))
      (when ok-states
        (unless (memq now-state ok-states)
          (bad-state now-state ok-states msg)))
         (when pre-state
           (set-state pre-state))
         (begin0 (proc now-state)
           (when post-state (set-state post-state))))))

(define (make-statelock init-state [desc #f])
  (statelock (make-semaphore 1) init-state desc))

(define (copy-statelock stl)
  (match-define (statelock _ state desc) stl)
  (statelock (make-semaphore 1) state desc))

;; ----------------------------------------

(struct digest-ctx state-ctx ())

(struct cipher-ctx state-ctx
  (encrypt?     ;; Boolean
   )
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   (define-struct-abbrevs cipher-ctx)
   (define (%to-write-prefixes self)
     (list* "ctx" (if (.encrypt? self) "encrypt" "decrypt")
            (cdr ($to-write-prefixes (.impl self)))))))

;; ============================================================
;; Inputs

;; An Input is one of
;; - Bytes
;; - String
;; - InputPort
;; - (bytes-range Bytes Nat Nat)
;; - (Listof Input)

;; bytes-range is alias for slice, except constructor and predicate check for bytes
(begin
  (require (for-syntax racket/base racket/struct-info scramble/struct-info)
           (only-in scramble/slice
                    slice
                    [struct:slice struct:bytes-range]
                    [bytes-slice? bytes-range?]
                    [slice-value bytes-range-bs]
                    [slice-start bytes-range-start]
                    [slice-end bytes-range-end]))
  (define (make-bytes-range bs start end)
    (unless (bytes? bs) (raise-argument-error 'bytes-range "bytes?" 0 bs start end))
    (slice bs start end))
  (define-syntax bytes-range
    (adjust-struct-info
     (list #'struct:bytes-range
           #'make-bytes-range
           #'bytes-range?
           (list #'bytes-range-end #'bytes-range-start #'bytes-range-bs)
           (list #f #f #f)
           #t))))

(define input/c
  (flat-rec-contract input/c
    (or/c bytes? string? input-port? bytes-range? (listof input/c))))

;; A Config is (listof (list Symbol Any))
(define config/c (listof (list/c symbol? any/c)))

;; An InternalContext is an impl-specific type.
(define ictx/c any/c)

(define key/c bytes?)
(define maybe-key/c (or/c bytes? #f))
(define iv/c (or/c bytes? #f))
(define maybe-size/c (or/c nat? #f))

;; ============================================================
;; Digests

(define-interface digest-impl$
  #:super (digest-info$)
  #:predicate digest-impl?
  (;; type Ctx = (digest-ctx _ Any)
   [digest      (-> digest-impl? input/c maybe-key/c maybe-size/c config/c bytes?)]
   [di-new-ctx  (-> digest-impl? maybe-key/c config/c digest-ctx?)]
   [di-update   (-> digest-impl? digest-ctx? input/c void?)]
   [di-final    (-> digest-impl? digest-ctx? maybe-size/c bytes?)]
   [di-copy     (-> digest-impl? digest-ctx? (or/c digest-ctx? #f))])
  #:generics-prefix $)


;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 for block ciphers, none for stream
(define cipher-pad/c boolean?)

(define-interface cipher-impl$
  #:super (cipher-info$)
  #:predicate cipher-impl?
  (;; type Ctx = (cipher-ctx _ Any)
   [ci-new-ctx      (-> cipher-impl? key/c iv/c boolean?
                        cipher-pad/c (or/c nat? #f) boolean?
                        cipher-ctx?)]
   [ci-update-aad   (-> cipher-impl? cipher-ctx? input/c void?)]
   [ci-update       (-> cipher-impl? cipher-ctx? input/c void?)]
   [ci-final        (-> cipher-impl? cipher-ctx? (or/c bytes? #f) void?)]
   [ci-get-output   (-> cipher-impl? cipher-ctx? bytes?)]
   [ci-auth-tag     (-> cipher-impl? cipher-ctx? (or/c bytes? #f))])
  #:generics-prefix $)

;; Sends {ciper,plain}text to given output port.
;; AEAD: auth tag length is set at ctx construction;
;; decrypt final takes auth tag (encrypt takes #f)


;; ============================================================
;; Public-Key Cryptography

(define pk-sign-pad/c (or/c #f 'pkcs1-v1.5 'pss 'pss*))
(define pk-enc-pad/c (or/c #f 'pkcs1-v1.5 'oaep))

;; types ParamValues, PubKeyValues, PrivKeyValues depend on spec, not impl:
;; - rsa: () ; (n e : Nat) ; (d p q dp dq qInv : Nat) -- (allow #f for priv components?)
;; - dsa: (p q g : Nat); (y : Nat) ; (x : Nat)
;; - dh:  (p g : Nat, q j : Nat/#f, seed : Bytes/#f, pgen : Nat/#f) ; (y : Nat) ; (x : Nat)
;; - ec:  (curve-alias : Symbol) ; (q : Bytes) ; (x : Nat)
;; - eddsa: (curve : (U 'ed25519 'ed448)) ; (q : Bytes) ; (d : Bytes)
;; - ecx: (curve : (U 'x25519 'x448)) ; (q : Bytes) ; (d : Bytes)

(struct pk-parameters ctx ()
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs pk-parameters)
   ;; ----
   (define (%to-write-prefixes self)
     (cons "pk-parameters" (cdr (super-to-write-prefixes self))))))

(struct pk-key ctx (private?)
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs pk-key)
   ;; ----
   (define (%to-write-prefixes self)
     (cons (if (.private? self) "private-key" "public-key")
           (cdr (super-to-write-prefixes self))))))

(define-interface pk-impl$
  #:super (pk-info$)
  #:predicate pk-impl?
  ([pk-generate-key     (-> pk-impl? config/c pk-key?)]
   [pk-generate-params  (-> pk-impl? config/c pk-parameters?)]

   [pk-make-params
    ;; PKImpl ParamValues... -> (U PKParameters #f)
    (unconstrained-domain-> (or/c pk-parameters? #f))]
   [pk-make-public-key
    ;; PKImpl ParamValues... PubKeyValues... -> (U PKKey #f)
    (unconstrained-domain-> (or/c pk-key? #f))]
   [pk-make-private-key
    ;; PKImpl ParamValues... PubKeyValues... PrivKeyValues... -> (U PKKey #f)
    (unconstrained-domain-> (or/c pk-key? #f))]

   ;; type PKP = (pk-parameters InnerParam)
   ;; type InnerParam
   [pkp-generate-key    (-> pk-impl? pk-parameters? pk-key?)]
   [pkp-write-params    (-> pk-impl? pk-parameters? symbol? any/c)]
   [pkp-security-bits   (-> pk-impl? pk-parameters? (or/c nat? #f))]
   [pkp-param-values    (-> pk-impl? pk-parameters? any)] ;; _ -> ParamValues
   [pkp-equal?          (-> pk-impl? pk-parameters? pk-parameters? boolean?)] ;; PRE: same impl

   ;; type PKK = (pk-key _ InnerKey _)
   ;; type InnerKey
   [pkk-public-key      (-> pk-impl? pk-key? pk-key?)]
   [pkk-params          (-> pk-impl? pk-key? (or/c pk-parameters? #f))]
   [pkk-security-bits   (-> pk-impl? pk-key? (or/c nat? #f))]
   [pkk-write-key       (-> pk-impl? pk-key? symbol? any/c)]
   [pkk-equal-public?   (-> pk-impl? pk-key? pk-key? boolean?)] ;; PRE: same impl
   [pkk-equal-params?   (-> pk-impl? pk-key? pk-key? boolean?)] ;; PRE: same impl

   [pkk-sign
    (->i ([self pk-impl?]
          [pkk pk-key?] [msg bytes?] [dspec (or/c digest-spec? 'none)] [pad pk-sign-pad/c])
         #:pre (self dspec pad) ($pk-can-sign? self pad dspec)
         [_ bytes?])]
   [pkk-verify
    (->i ([self pk-impl?]
          [pkk pk-key?] [msg bytes?] [dspec (or/c digest-spec? 'none)] [pad pk-sign-pad/c]
          [sig bytes?])
         #:pre (self dspec pad) ($pk-can-sign? self pad dspec)
         [_ boolean?])]
   ;; In verify, if sig is not well-formed then just return #f, no error.

   [pkk-encrypt
    (->i ([self pk-impl?] [pkk pk-key?] [msg bytes?] [pad pk-enc-pad/c])
         #:pre (self pad) ($pk-can-encrypt? self pad)
         [_ bytes?])]
   [pkk-decrypt
    (->i ([self pk-impl?] [pkk pk-key?] [msg bytes?] [pad pk-enc-pad/c])
         #:pre (self pad) ($pk-can-encrypt? self pad)
         [_ bytes?])]

   [pkk-compute-secret
    (->i ([self pk-impl?] [pkk pk-key?] [peer (or/c bytes? pk-key?)])
         #:pre (self) ($pk-can-key-agree? self)
         ;; PRE: pkk, peer both belong to self, same spec, same params
         [_ bytes?])]
   [pkk-import-for-key-agree
    (-> pk-impl? pk-key? bytes?
        pk-key?)])
  #:fallbacks
  (let ()
    (define (pk-make-params self . _) #f)
    (define (pk-make-public-key self . _) #f)
    (define (pk-make-private-key self . _) #f)
    (hasheq 'pk-make-params pk-make-params
            'pk-make-public-key pk-make-public-key
            'pk-make-private-key pk-make-private-key))
  #:generics-prefix $)

(define (pk-import-parsed pk parsed)
  (match parsed
    [(list* pkspec keytype vs)
     #:when (eq? pkspec ($get-spec pk))
     (case keytype
       [(PARAMS) (apply $pk-make-params pk vs)]
       [(PUBLIC) (apply $pk-make-public-key pk vs)]
       [(SECRET) (apply $pk-make-private-key pk vs)])]
    [_ #f]))

;; Import key from different impl, must be same pkspec
(define (pk-import-key pk pkk public?)
  (define fmt (if public? 'internal-public 'internal))
  (define datum ($pkk-write-key (ctx-impl pkk) pkk fmt))
  (pk-import-parsed pk datum))

(define (pk-compare-key-data pkk1 pkk2 fmt)
  (define internal1 ($pkk-write-key (ctx-impl pkk1) pkk1 fmt))
  (define internal2 ($pkk-write-key (ctx-impl pkk2) pkk2 fmt))
  (unless (and internal1 internal2)
    (internal-error "failure comparing keys\n  key 1: ~e\n  key 2: ~e" pkk1 pkk2))
  (equal? internal1 internal2))

(define (pk-compare-param-data pkp1 pkp2 fmt)
  (define internal1 ($pkp-write-params (ctx-impl pkp1) pkp1 fmt))
  (define internal2 ($pkp-write-params (ctx-impl pkp2) pkp2 fmt))
  (unless (and internal1 internal2)
    (internal-error "failure comparing params\n  params 1: ~e\n  params 2: ~e" pkp1 pkp2))
  (equal? internal1 internal2))

;; ============================================================
;; KDFs

(define-interface kdf-impl$
  #:super (kdf-info$)
  #:predicate kdf-impl?
  ([kdf-derive    (-> kdf-impl? (or/c nat? #f) config/c bytes? (or/c bytes? #f)
                      bytes?)]
   [pwhash        (-> kdf-impl? config/c bytes?
                      string?)]
   [pwhash-verify (-> kdf-impl? bytes? string?
                      boolean?)])
  #:generics-prefix $)

;; ============================================================
;; Implementation Factories

(define-interface factory$
  #:predicate factory?
  ([factory-print     (-> factory? void?)]
   [factory-info      (-> factory? symbol? any)]
   [factory-name      (-> factory? symbol?)]
   [factory-version   (-> factory? (listof exact-nonnegative-integer?))] ;; '() allowed
   [factory-display-name (-> factory? string?)]
   [factory-inner-ctx (-> factory? any/c)]
   [fetch-digest      (-> factory? digest-spec? (or/c digest-impl? #f))]
   [fetch-cipher      (-> factory? cipher-spec? (or/c cipher-impl? #f))]
   [fetch-pk          (-> factory? pk-spec?     (or/c pk-impl? #f))]
   [fetch-kdf         (-> factory? kdf-spec?    (or/c kdf-impl? #f))])
  #:generics-prefix $)

(define (import-parsed impl parsed)
  (match impl
    [(? factory? factory)
     (match parsed
       [(cons pkspec _)
        (let ([pk ($fetch-pk factory pkspec)])
          (and pk (pk-import-parsed pk parsed)))]
       [_ #f])]
    [(? pk-impl? pki)
     (pk-import-parsed pki parsed)]))
