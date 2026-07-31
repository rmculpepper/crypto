;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract/base
         (only-in racket/base [exact-nonnegative-integer? nat?])
         "methods.rkt"
         "catalog.rkt")
(provide (all-defined-out))

;; ============================================================
;; General Notes

;; All sizes are expressed as a number of bytes unless otherwise noted.
;; eg, (send a-sha1-impl get-size) => 20

;; Whenever a string S is accepted as an input, it is interpreted as
;; equivalent to (string->bytes/utf-8 S).

;; ============================================================
;; Predicates

(define (crypto-factory? x) (factory$? x))
(define (digest-impl? x) (digest-impl$? x))
(define (cipher-impl? x) (cipher-impl$? x))
(define (pk-impl? x) (pk-impl$? x))
(define (kdf-impl? x) (kdf-impl$? x))

(struct ctx (impl ctx))
(struct digest-ctx ctx ())
(struct cipher-ctx ctx ())
(struct pk-parameters ctx ())
(struct pk-key ctx ())

(define info/c any/c)
(define spec/c any/c)

;; ============================================================
;; Util

(define-interface about$
  (about    ;; -> String
   )
  #:generics-prefix $)


;; ============================================================
;; General Implementation & Contexts

(define-interface impl$
  #:super (about$ info$)
  (impl-info    ;; -> Info
   impl-factory ;; -> Factory
   )
  #:generics-prefix $)

(define-interface state$
  (call-with-state   ;; [#:ok States #:pre State #:post State #:msg Any] (-> Any) -> Any
   ;; Acquires mutex, checks state, and updates state before and after calling proc.
   )
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
#;
(struct bytes-range (bs start end)
  #:guard (lambda (buf start end _name)
            (unless (bytes? buf)
              (raise-argument-error 'bytes-range "bytes?" 0 buf start end))
            (unless (exact-nonnegative-integer? start)
              (raise-argument-error 'bytes-range "exact-nonnegative-integer?" 1 buf start end))
            (unless (exact-nonnegative-integer? end)
              (raise-argument-error 'bytes-range "exact-nonnegative-integer?" 2 buf start end))
            (unless (<= start end (bytes-length buf))
              (raise-range-error 'bytes-range "bytes" "ending " end buf start (bytes-length buf) 0))
            (values buf start end)))

(define input/c
  (flat-rec-contract input/c
    (or/c bytes? string? input-port? bytes-range? (listof input/c))))

;; A Config is (listof (list Symbol Any))
(define config/c (listof (list/c symbol? any/c)))


;; ============================================================
;; Implementation Factories

(define-interface factory$
  (factory-version  ;; -> (U #f (Listof Nat))
   factory-info     ;; Symbol -> Any
   factory-print    ;; -> Void
   factory-name     ;; -> Symbol
   fetch-digest     ;; DigestSpec -> (U DigestImpl #f)
   fetch-cipher     ;; CipherSpec -> (U CipherImpl #f)
   fetch-pk         ;; PKSpec -> (U PKImpl #f)
   fetch-kdf        ;; KDFSpec -> (U KDFImpl #f)
   factory-import-pk    ;; Any -> (U PKKey PKParameters #f)
   )
  #:generics-prefix $)


;; ============================================================
;; Digests

(define-interface digest-impl$
  #:super (impl$ digest-info$)
  (digest       ;; Input (U Bytes #f) (U Nat #f) Config -> Bytes
   di-new-ctx   ;; (U Bytes #f) Config -> DigestIntCtx
   di-update    ;; DigestIntCtx Input -> Void
   di-final     ;; DigestIntCtx (U Nat #f) -> Bytes
   di-copy      ;; DigestIntCtx -> (U DigestCtx #f)
   )
  #:generics-prefix $)

;; DigestIntCtx is private per-impl type.
;; DigestCtx is public wrapper (see digest.rkt).


;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 for block ciphers, none for stream
(define cipher-pad/c boolean?)

(define-interface cipher-impl$
  #:super (impl$ cipher-info$)
  (ci-new-ctx      ;; Bytes (U Bytes #f) Boolean PadMode (U Nat #f) Boolean -> CipherIntCtx
   ci-get-encrypt? ;; CipherIntCtx -> Boolean
   ci-update-aad   ;; CipherIntCtx Input -> ??
   ci-update       ;; CipherIntCtx Input -> ??
   ci-final        ;; CipherIntCtx (U Bytes #f) -> ??
   ci-auth-tag     ;; CipherIntCtx -> (U Bytes #f)
   )
  #:generics-prefix $)

;; CipherIntCtx is private per-impl type.
;; CipherCtx is public wrapper (see cipher.rkt).

;; Sends {ciper,plain}text to given output port.
;; AEAD: auth tag length is set at ctx construction;
;; decrypt final takes auth tag (encrypt takes #f)


;; ============================================================
;; Public-Key Cryptography

(define pk-config/c (listof (list/c symbol? any/c)))
(define pk-sign-pad/c (or/c #f 'pkcs1-v1.5 'pss 'pss*))
(define pk-enc-pad/c (or/c #f 'pkcs1-v1.5 'oaep))

(define-interface pk-impl$
  #:super (impl$ pk-info$)
  (pk-generate-key      ;; PKConfig -> PKKey
   pk-generate-params   ;; PKConfig -> PKParameters
   pk-import-pk         ;; Any -> (U PKKey PKParameters #f)

   pkp-generate-key     ;; PKParameters PKConfig -> PKKey
   pkp-write-params     ;; PKParameters Symbol -> Any
   pkp-security-bits    ;; PKParameters -> (U Nat #f)
   pkp-curve            ;; PKParameters -> (U Symbol #f)

   pkk-is-private?      ;; PKKey -> Boolean
   pkk-public-key       ;; PKKey -> PKKey
   pkk-params           ;; PKKey -> (U PKParameters #f)
   pkk-security-bits    ;; PKKey -> (U Nat #f)

   pkk-write-key        ;; PKKey Symbol -> Any
   pkk-public-equal?    ;; PKKey PKKey -> Boolean

   pkk-sign             ;; PKKey Bytes (U DigestSpec #f) PKSignPad -> Bytes
   pkk-verify           ;; PKKey Bytes (U DigestSpec #f) PKSignPad Bytes -> Boolean
   ;; In verify, if sig is not well-formed then just return #f, no error.

   pkk-encrypt          ;; PKKey Bytes PKEncPad -> Bytes
   pkk-decrypt          ;; PKKey Bytes PKEncPad -> Bytes

   pkk-compute-secret   ;; PKKey (U Bytes PKKey) -> Bytes
   )
  #:generics-prefix $)


;; ============================================================
;; KDFs

(define kdf-params/c (listof (list/c symbol? any/c)))

(define-interface kdf-impl$
  #:super (impl$ kdf-info$)
  (kdf-derive   ;; (U Nat #f) KDFParams Bytes (U Bytes #f) -> Bytes
   )
  #:generics-prefix $)
