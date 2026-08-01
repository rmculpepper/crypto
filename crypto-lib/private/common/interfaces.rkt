;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/contract/base
         scramble/bundle
         scramble/struct
         "catalog.rkt")
(provide (all-defined-out))

;; ============================================================
;; General Notes

;; All sizes are expressed as a number of bytes unless otherwise noted.
;; eg, (send a-sha1-impl get-size) => 20

;; Whenever a string S is accepted as an input, it is interpreted as
;; equivalent to (string->bytes/utf-8 S).

;; ============================================================

(define (crypto-factory? x) (factory? x))

(struct ctx (impl ic)
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   (define-struct-abbrevs ctx)
   ;; ----
   (define (%to-write-string self)
     ($to-write-string (.impl self)))
   (define (%to-write-prefixes self)
     (cons "ctx" (cdr ($to-write-prefixes (.impl self)))))))

;; ============================================================
;; General Implementation & Contexts

(define-interface impl$
  #:super (info$ simple-write$)
  ([impl-info     (-> impl$? info?)]
   [impl-factory  (-> impl$? crypto-factory?)])
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
;; Digests

(define-interface digest-impl$
  #:super (impl$ digest-info$)
  #:predicate digest-impl?
  ([digest      (-> digest-impl? input/c (or/c bytes? #f) (or/c nat? #f) config/c
                    bytes?)]
   [di-new-ctx  (-> digest-impl? (or/c bytes? #f) config/c ctx?)]
   [di-update   (-> digest-impl? ctx? bytes? nat? nat? void?)]
   [di-final    (-> digest-impl? ctx? bytes?)]
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
  ([ci-new-ctx      (-> cipher-impl? bytes? (or/c bytes? #f) boolean?
                        cipher-pad/c (or/c nat? #f) boolean?
                        ctx?)]
   [ci-get-encrypt? (-> cipher-impl? ctx? boolean?)]
   [ci-update-aad   (-> cipher-impl? ctx? input/c void?)]
   [ci-update       (-> cipher-impl? ctx? input/c void?)]
   [ci-final        (-> cipher-impl? ctx? (or/c bytes? #f) any)] ;; FIXME
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
   #:import ([simple-write$ #:super #:prefix super-])
   (define-struct-abbrevs pk-parameters)
   ;; ----
   (define (%to-write-prefixes self)
     (cons "pk-parameters" (cdr (super-to-write-prefixes self))))))

(struct pk-key ctx ()
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   #:import ([simple-write$ #:super #:prefix super-])
   (define-struct-abbrevs pk-key)
   ;; ----
   (define (%to-write-prefixes self)
     (cons (if ($pkk-is-private? (.impl self)) "private-key" "public-key")
           (cdr (super-to-write-prefixes self))))))

(define-interface pk-impl$
  #:super (impl$ pk-info$)
  #:predicate pk-impl?
  ([pk-generate-key     (-> pk-impl? config/c pk-key?)]
   [pk-generate-params  (-> pk-impl? config/c pk-parameters?)]
   [pk-import-pk        (-> pk-impl? any/c (or/c pk-key? pk-parameters? #f))]

   [pkp-generate-key    (-> pk-impl? pk-parameters? config/c pk-key?)]
   [pkp-write-params    (-> pk-impl? pk-parameters? symbol? any/c)]
   [pkp-security-bits   (-> pk-impl? pk-parameters? (or/c nat? #f))]
   [pkp-curve           (-> pk-impl? pk-parameters? (or/c symbol? #f))]

   [pkk-is-private?     (-> pk-impl? pk-key? boolean?)]
   [pkk-public-key      (-> pk-impl? pk-key? pk-key?)]
   [pkk-params          (-> pk-impl? pk-key? (or/c pk-parameters? #f))]
   [pkk-security-bits   (-> pk-impl? pk-key? (or/c nat? #f))]
   [pkk-write-key       (-> pk-impl? pk-key? symbol? any/c)]
   [pkk-public-equal?   (-> pk-impl? pk-key? pk-key? boolean?)]

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
  ([kdf-derive  (-> kdf-impl? (or/c nat? #f) config/c bytes? (or/c bytes? #f)
                    bytes?)])
  #:generics-prefix $)

;; ============================================================
;; Implementation Factories

(define-interface factory$
  #:super (simple-write$)
  #:predicate factory?
  ([factory-print     (-> factory? void?)]
   [factory-info      (-> factory? symbol? any)]
   [factory-name      (-> factory? symbol?)]
   [factory-version   (-> factory? (or/c (listof exact-nonnegative-integer?) #f))]
   [fetch-digest      (-> factory? digest-spec? (or/c digest-impl? #f))]
   [fetch-cipher      (-> factory? cipher-spec? (or/c cipher-impl? #f))]
   [fetch-pk          (-> factory? pk-spec?     (or/c pk-impl? #f))]
   [fetch-kdf         (-> factory? kdf-spec?    (or/c kdf-impl? #f))]
   [factory-import-pk (-> factory? any/c        (or/c pk-key? pk-parameters? #f))])
  #:generics-prefix $)
