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

;; ------------------------------------------------------------

(define-interface has-info$
  #:predicate has-info?
  ([get-info    (-> has-info? info?)])
  #:generics-prefix $)

(define-interface has-factory$
  #:predicate has-factory?
  ([get-factory (-> has-factory? crypto-factory?)])
  #:generics-prefix $)

;; ============================================================

(struct ctx (impl [inner #:mutable])
  #:properties
  (method-properties
   #:export ([has-spec$ #:prefix %]
             [has-info$ #:prefix %]
             [has-factory$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs ctx)
   ;; ----
   (define (%get-spec self) ($get-spec ($get-info self)))
   (define (%get-info self) ($get-info (.impl self)))
   (define (%get-factory self) ($get-factory (.impl self)))
   ;; ----
   (define (%to-write-string self)
     ($to-write-string (.impl self)))
   (define (%to-write-prefixes self)
     (cons "ctx" (cdr ($to-write-prefixes (.impl self)))))))

;; ----------------------------------------

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
;; General Implementation & Contexts

(define-interface impl$
  #:super (info$ has-info$ has-factory$)
  #:predicate impl?
  ())

;; ----------------------------------------

(struct info-impl-base (info factory)
  #:properties
  (method-properties
   #:export ([impl$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info-impl-base)
   ;; ----
   (define (%get-spec self) ($get-spec (.info self)))
   (define (%get-info self) (.info self))
   (define (%get-factory self) (.factory self))
   ;; ----
   (define (%to-write-string self)
     (format "~s" ($get-spec self)))
   (define (%to-write-prefixes self)
     (list ($factory-name (.factory self))))))

;; ----------------------------------------

#;
(define-interface clone$
  (clone
   prepare-clone   ;; -> (values (X ... -> Self) (Listof X) (Self -> Void))
   )
  #:fallbacks
  (let ()
    (define (clone self)
      (define-values (maker args patchup) ($prepare-clone self))
      (define copy (apply maker args))
      (patchup copy)
      copy)
    (define (prepare-clone self)
      (define (invalid . args) (error 'clone "invalid constructor"))
      (values invalid null void))
    (hasheq 'clone clone 'prepare-clone prepare-clone))
  #:generics-prefix $)

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
  #:super (impl$ digest-info$)
  #:predicate digest-impl?
  ([digest      (-> digest-impl? input/c maybe-key/c maybe-size/c config/c
                    bytes?)]
   [di-new-ctx  (-> digest-impl? maybe-key/c config/c ctx?)]
   [di-update   (-> digest-impl? ctx? input/c void?)]
   [di-final    (-> digest-impl? ctx? maybe-size/c bytes?)]
   [di-copy     (-> digest-impl? ctx? (or/c ctx? #f))])
  #:generics-prefix $)


;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 for block ciphers, none for stream
(define cipher-pad/c boolean?)

(define-interface cipher-impl$
  #:super (impl$ cipher-info$)
  #:predicate cipher-impl?
  ([ci-new-ctx      (-> cipher-impl? key/c iv/c boolean?
                        cipher-pad/c (or/c nat? #f) boolean?
                        ctx?)]
   [ci-update-aad   (-> cipher-impl? ctx? input/c void?)]
   [ci-update       (-> cipher-impl? ctx? input/c void?)]
   [ci-final        (-> cipher-impl? ctx? (or/c bytes? #f) void?)]
   [ci-get-output   (-> cipher-impl? ctx? bytes?)]
   [ci-auth-tag     (-> cipher-impl? ctx? (or/c bytes? #f))])
  #:generics-prefix $)

;; Sends {ciper,plain}text to given output port.
;; AEAD: auth tag length is set at ctx construction;
;; decrypt final takes auth tag (encrypt takes #f)


;; ============================================================
;; Public-Key Cryptography

(define pk-sign-pad/c (or/c #f 'pkcs1-v1.5 'pss 'pss*))
(define pk-enc-pad/c (or/c #f 'pkcs1-v1.5 'oaep))

(struct pk-parameters ctx ()
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs pk-parameters)
   ;; ----
   (define (%to-write-prefixes self)
     (cons "pk-parameters" (cdr (super-to-write-prefixes self))))))

(define (pk-p-generate-key pkp)
  ($pkp-generate-key (ctx-impl pkp) pkp))
(define (pk-p-write-params pkp fmt)
  ($pkp-write-params (ctx-impl pkp) pkp fmt))
(define (pk-p-security-bits pkp)
  ($pkp-security-bits (ctx-impl pkp) pkp))
(define (pk-p-param-values pkp)
  ($pkp-param-values (ctx-impl pkp) pkp))

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

(define (pk-k-public-key pkk)
  ($pkk-public-key (ctx-impl pkk) pkk))
(define (pk-k-params pkk)
  ($pkk-params (ctx-impl pkk) pkk))
(define (pk-k-security-bits pkk)
  ($pkk-security-bits (ctx-impl pkk) pkk))
(define (pk-k-write-key pkk fmt)
  ($pkk-write-key (ctx-impl pkk) pkk fmt))
(define (pk-k-sign pkk msg dspec pad)
  ($pkk-sign (ctx-impl pkk) pkk msg dspec pad))
(define (pk-k-verify pkk msg dspec pad sig)
  ($pkk-verify (ctx-impl pkk) pkk msg dspec pad sig))
(define (pk-k-encrypt pkk msg pad)
  ($pkk-encrypt (ctx-impl pkk) pkk msg pad))
(define (pk-k-decrypt pkk msg pad)
  ($pkk-decrypt (ctx-impl pkk) pkk msg pad))
(define (pk-k-compute-secret pkk peer-pubkey)
  ($pkk-compute-secret (ctx-impl pkk) pkk peer-pubkey))

(define-interface pk-import$
  #:predicate pk-import?
  ([pk-import-pk (-> pk-import? any/c (or/c pk-key? pk-parameters? #f))])
  #:generics-prefix $)

(define-interface pk-impl$
  #:super (impl$ pk-info$ pk-import$)
  #:predicate pk-impl?
  ([pk-generate-key     (-> pk-impl? config/c pk-key?)]
   [pk-generate-params  (-> pk-impl? config/c pk-parameters?)]
   [pk-import-key       (-> pk-impl? pk-key? boolean? pk-key?)]

   [pkp-generate-key    (-> pk-impl? pk-parameters? pk-key?)]
   [pkp-write-params    (-> pk-impl? pk-parameters? symbol? any/c)]
   [pkp-security-bits   (-> pk-impl? pk-parameters? (or/c nat? #f))]
   [pkp-param-values    (-> pk-impl? pk-parameters? any)] ;; result type varies
   [pkp-equal?          (-> pk-impl? pk-parameters? pk-parameters? boolean?)]

   [pkk-public-key      (-> pk-impl? pk-key? pk-key?)]
   [pkk-params          (-> pk-impl? pk-key? (or/c pk-parameters? #f))]
   [pkk-security-bits   (-> pk-impl? pk-key? (or/c nat? #f))]
   [pkk-write-key       (-> pk-impl? pk-key? symbol? any/c)]
   [pkk-equal-public?   (-> pk-impl? pk-key? pk-key? boolean?)]
   [pkk-equal-params?   (-> pk-impl? pk-key? pk-key? boolean?)]

   [pkk-sign            (-> pk-impl? pk-key? bytes?
                            (or/c digest-spec? #f) pk-sign-pad/c
                            bytes?)]
   [pkk-verify          (-> pk-impl? pk-key? bytes?
                            (or/c digest-spec? #f) pk-sign-pad/c bytes?
                            boolean?)]
   ;; In verify, if sig is not well-formed then just return #f, no error.

   [pkk-encrypt         (-> pk-impl? pk-key? bytes? pk-enc-pad/c bytes?)]
   [pkk-decrypt         (-> pk-impl? pk-key? bytes? pk-enc-pad/c bytes?)]

   [pkk-compute-secret  (-> pk-impl? pk-key? (or/c bytes? pk-key?) bytes?)])
  #:generics-prefix $)

;; ============================================================
;; KDFs

(define-interface kdf-impl$
  #:super (impl$ kdf-info$)
  #:predicate kdf-impl?
  ([kdf-derive    (-> kdf-impl? (or/c nat? #f) config/c bytes? (or/c bytes? #f)
                      bytes?)]
   [pwhash        (-> kdf-impl? config/c bytes?
                      string?)]
   [pwhash-verify (-> kdf-impl? config/c string?
                      boolean?)])
  #:generics-prefix $)

;; ============================================================
;; Implementation Factories

(define-interface factory$
  #:super (pk-import$)
  #:predicate factory?
  ([factory-print     (-> factory? void?)]
   [factory-info      (-> factory? symbol? any)]
   [factory-name      (-> factory? symbol?)]
   [factory-version   (-> factory? (listof exact-nonnegative-integer?))] ;; '() allowed
   [factory-display-name (-> factory? string?)]
   [fetch-digest      (-> factory? digest-spec? (or/c digest-impl? #f))]
   [fetch-cipher      (-> factory? cipher-spec? (or/c cipher-impl? #f))]
   [fetch-pk          (-> factory? pk-spec?     (or/c pk-impl? #f))]
   [fetch-kdf         (-> factory? kdf-spec?    (or/c kdf-impl? #f))])
  #:generics-prefix $)
