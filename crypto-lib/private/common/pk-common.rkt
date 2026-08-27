;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/contract/base
         brandx
         asn1
         binaryio/integer
         base64
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "base256.rkt"
         "asn1.rkt"
         "pk-format.rkt")
(provide (all-defined-out)
         (all-from-out "pk-format.rkt")
         curve-name->oid
         curve-oid->name)

;; ============================================================
;; Base classes

(struct pk-impl-base info-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs pk-impl-base)
   (define (%to-write-prefixes self)
     (list* "impl" "pk" (super-to-write-prefixes self)))

   ;; ---- pk-info

   ;; Implementations vary so much, must override.
   (define (%pk-can-sign? self pad dspec) #f)
   (define (%pk-can-encrypt? self pad) #f)

   (define (%pk-can-key-agree? self)
     ($pk-can-key-agree? (.info self)))
   (define (%pk-has-params? self)
     ($pk-has-params? (.info self)))

   ;; ---- pk-impl

   (define (%pk-generate-key self config)
     (cond [($pk-has-params? self)
            (define p ($pk-generate-params self config))
            ($pkp-generate-key self p)]
           [else (err/no-impl self)]))

   (define (%pk-generate-params self config)
     (cond [($pk-has-params? self) (err/no-impl self)]
           [else (crypto-error "key parameters not supported" #:in self)]))

   ;; Called by datum->pk-{key,parameters}%, signature depends on spec
   (define (%pk-import-pk self parsed)
     (match parsed
       [(list* (== ($get-spec self)) keytype vs)
        (case keytype
          [(PARAMS) (apply $pk-make-params self vs)]
          [(PUBLIC) (apply $pk-make-public-key self vs)]
          [(SECRET) (apply $pk-make-private-key self vs)])]
       [_ #f]))

   ;; ---- pkp

   ;; pkp-generate-key
   ;; pkp-param-values

   (define (%pkp-write-params self pkp fmt)
     (case ($get-spec self)
       [(dsa)
        ;; (values Nat Nat Nat)
        (define-values (p q g) ($pkp-param-values self pkp))
        (encode-params-dsa fmt p q g)]
       [(dh)
        ;; (values Nat Nat Nat/#f Nat/#f Bytes/#f Nat/#f)
        (define-values (p g q j seed pgen) ($pkp-param-values self pkp))
        (encode-params-dh fmt p g q j seed pgen)]
       [(ec)
        (define curve-alias ($pkp-param-values self pkp))
        (define curve-oid (curve-alias->oid curve-alias))
        (encode-params-ec fmt curve-oid)]
       [(eddsa)
        (define curve-name ($pkp-param-values self pkp))
        (encode-params-eddsa fmt curve-name)]
       [(ecx)
        (define curve-name ($pkp-param-values self pkp))
        (encode-params-ecx fmt curve-name)]
       [else #f]))

   (define (%pkp-security-bits self pkp)
     (rkt-params-security-bits
      ($pkp-write-params self pkp 'rkt-params)))

   (define (%pkp-equal? self pkp1 pkp2)
     (pk-compare-param-data pkp1 pkp2))

   ;; ---- pkk

   ;; pkk-write-key

   (define (%pkk-public-key self pkk)
     (cond [(pk-key-private? pkk)
            ($pk-import-pk self ($pkk-write-key self pkk 'internal-public))]
           [else pkk]))

   (define (%pkk-params self pkk)
     (cond [($pk-has-params? self)
            ($pk-import-pk self ($pkk-write-key self pkk 'internal-params))]
           [else (crypto-error "key parameters not supported" #:in pkk)]))

   (define (%pkk-security-bits self pkk)
     (if ($pk-has-params? self)
         ($pkp-security-bits self ($pkk-params self pkk))
         (parsed-pkey-security-bits ($pkk-write-key self pkk 'internal-public))))

   (define (%pkk-equal-params? self pkk1 pkk2)
     (pk-compare-key-data pkk1 pkk2 'internal-params))

   (define (%pkk-equal-public? self pkk1 pkk2)
     (pk-compare-key-data pkk1 pkk2 'internal-public))
   ))

;; ============================================================

(struct keypair (param pub priv))

(struct keypair-pk-impl-base pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %])
   #:import ([pk-impl$ #:super])

   ;; type PKP <: (pk-parameters InnerParam)
   ;; type InnerParam

   ;; type PKK <: (pk-key _ InnerKey _)
   ;; type InnerKey <: (keypair InnerParam InnerPub InnerPriv)
   ;; type InnerPub, InnerPriv

   (define (%pkk-public-key self pkk)
     (match-define (pk-key impl (keypair param pub priv) private?) pkk)
     (if private? (pk-key impl (keypair param pub #f) #f) pkk))

   (define (%pkk-params self pkk)
     (cond [($pk-has-params? self)
            (define param (keypair-param (ctx-inner pkk)))
            (pk-parameters self param)]
           [else (super-pkk-params self pkk)]))
   ))

;; ----------------------------------------

(define-interface curve-ok$
  ([curve-ok? (-> curve-ok$? symbol? boolean?)])
  #:generics-prefix $)

;; abstract class where param is represented by curve name (symbol)
(struct curve-pk-impl-base keypair-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   ;; type InnerParam = Symbol, curve name

   (define (%pkp-param-values self pkp)
     (define curve-name (ctx-inner pkp))
     curve-name)

   (define (%pk-make-params self curve)
     (and ($curve-ok? self curve)
          (pk-parameters self curve)))
   ))

;; ----------------------------------------

;; abstract class for eddsa where pub, priv are bytestrings
(struct eddsa-impl-base curve-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   ;; type InnerPub = Bytes
   ;; type InnerPriv = Bytes

   (define (%pk-generate-params self config)
     (check-config config config:eddsa-keygen #:in self)
     (define curve (config-ref config 'curve))
     (or ($pk-make-params self curve)
         (err/no-curve curve self)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     ;; accommodate sodium, which sets priv = priv-seed || pub
     (cond [priv (let ([priv (subbytes priv 0 (eddsa-keylen curve))])
                   (encode-priv-eddsa fmt curve pub priv))]
           [else (encode-pub-eddsa fmt curve pub)]))

   (define (%pk-make-public-key self curve qB)
     (cond [($curve-ok? self curve)
            (define pub (eddsa-check-keys curve qB))
            (pk-key self (keypair curve pub #f) #f)]
           [else #f]))
   ))

;; length of public and private key components
(define (eddsa-keylen curve)
  (match curve
    ['ed25519 32]
    ['ed448 57]))

(define (eddsa-check-keys curve private? k1 [k2 #f])
  (eddsa/ecx-check-keys curve private? k1 k2 (eddsa-keylen curve)))

(define (eddsa/ecx-check-keys curve private? k1 k2 len)
  (define what1 (if private? "private" "public"))
  (define what2 (if private? "public" "private"))
  (unless (bytes? k1)
    (crypto-error "missing ~a key component" what1))
  (unless (= (bytes-length k1) len)
    (crypto-error "invalid ~a key (wrong length)" what1))
  (when k2
    (unless (= (bytes-length k2) len)
      (crypto-error "invalid ~a key (wrong length)" what2)))
  (bytes->immutable-bytes k1))

;; ----------------------------------------

;; abstract class for ecx where pub, priv are bytestrings
(struct ecx-impl-base curve-pk-impl-base ()
  #:properties
  (method-properties
   #:export ([pk-impl$ #:prefix %]
             [curve-ok$ #:prefix %])

   ;; type InnerPub = Bytes
   ;; type InnerPriv = Bytes

   (define (%pk-generate-params self config)
     (check-config config config:ecx-keygen #:in self)
     (define curve (config-ref config 'curve))
     (or ($pk-make-params self curve)
         (err/no-curve curve self)))

   (define (%pkk-write-key self pkk fmt)
     (match-define (keypair curve pub priv) (ctx-inner pkk))
     (cond [priv (encode-priv-ecx fmt curve pub priv)]
           [else (encode-pub-ecx fmt curve pub)]))

   (define (%pk-make-public-key self curve qB)
     (cond [($curve-ok? curve)
            (define pub (ecx-check-keys curve  qB))
            (pk-key self (keypair curve qB #f) #f)]
           [else #f]))

   (define (%pkk-import-for-key-agree self pkk bs)
     (define curve (keypair-param (ctx-inner pkk)))
     ($pk-make-public-key self curve bs))
   ))

;; length of public and private key components and derived secret
(define (ecx-keylen curve)
  (match curve
    ['x25519 32]
    ['x448 56]))

(define (ecx-check-keys curve private? k1 [k2 #f])
  (eddsa/ecx-check-keys curve private? k1 k2 (ecx-keylen curve)))

;; ============================================================

#;
(struct pk-curve pk-parameters
  (curve
   )
  #:properties
  (method-properties
   #:export ([simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs pk-curve)
   (define (%to-write-string self)
     (format "~a:~a" (super-to-write-string self) (.curve self)))
   ))

;; ============================================================

;; EC public key = ECPoint = octet string
;; EC private key = unsigned integer

;; Reference: SEC1 Section 2.3
;; We assume no compression, valid, not infinity, prime field.
;; mlen = ceil(bitlen(p) / 8), where q is the field in question.

;; ec-point->bytes : Nat Nat -> Bytes
(define (ec-point->bytes mlen x y)
  ;; no compression, assumes valid, assumes not infinity/zero point
  ;; (eprintf "encode\n mlen=~v\n x=~v\n y=~v\n" mlen x y)
  (bytes-append (bytes #x04) (integer->bytes x mlen #f #t) (integer->bytes y mlen #f #t)))

;; bytes->ec-point : Bytes -> (cons Nat Nat)
(define (bytes->ec-point buf)
  (define (bad) (crypto-error "failed to parse ECPoint (invalid)"))
  (define buflen (bytes-length buf))
  (unless (> buflen 0) (bad))
  (case (bytes-ref buf 0)
    [(#x02 #x03) ;; compressed point
     (crypto-error "failed to parse compressed ECPoint (not implemented)")]
    [(#x04) ;; uncompressed point
     (unless (odd? buflen) (bad))
     (define len (quotient (sub1 (bytes-length buf)) 2))
     (define x (bytes->integer buf #f #t 1 (+ 1 len)))
     (define y (bytes->integer buf #f #t (+ 1 len) (+ 1 len len)))
     ;; (eprintf "decode\n mlen=~v\n x=~v\n y=~v\n" len x y)
     (cons x y)]
    [else (bad)]))

;; check-recomputed-qB : Bytes (U Bytes #f) -> Void
(define (check-recomputed-qB new-qB maybe-old-qB)
  (when maybe-old-qB
    (unless (equal? new-qB maybe-old-qB)
      (crypto-error "public key does not match private key"))))

;; ============================================================
;; ECX Clamping

;; Reference: https://datatracker.ietf.org/doc/html/rfc7748, Section 5

;; Check if bytestring has X{25519,448} clamping applied.
(define (ecx-secret-wf? curve priv)
  (case curve
    [(x25519)
     (and (= (bytes-length priv) 32)
          (= #b000 (bitwise-and #b111 (bytes-ref priv 0)))
          (= #b01000000 (bitwise-and #b11000000 (bytes-ref priv 31))))]
    [(x448)
     (and (= (bytes-length priv) 56)
          (= #b00 (bitwise-and #b11 (bytes-ref priv 0)))
          (= #b10000000 (bitwise-and #b10000000 (bytes-ref priv 55))))]))

;; Modify bytestring, apply X{25519,448} secret key clamping.
(define (ecx-clamp-secret! curve priv)
  (case curve
    [(x25519)
     (unless (= (bytes-length priv) 32)
       (internal-error 'x25519-clamp-secret! "wrong length"))
     (bytes-set! priv 0  (bitwise-and #b11111000 (bytes-ref priv 0)))
     (bytes-set! priv 31 (bitwise-and #b01111111 (bytes-ref priv 31)))
     (bytes-set! priv 31 (bitwise-ior #b01000000 (bytes-ref priv 31)))]
    [(x448)
     (unless (= (bytes-length priv) 56)
       (internal-error 'x448-clamp-secret! "wrong length"))
     (bytes-set! priv 0  (bitwise-and #b11111100 (bytes-ref priv 0)))
     (bytes-set! priv 55 (bitwise-ior #b10000000 (bytes-ref priv 55)))]))

;; ============================================================

(define config:rsa-keygen
  `((nbits ,exact-positive-integer? #f #:opt 2048)
    (e     ,exact-positive-integer? #f #:opt #f)))

(define config:dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?"    #:opt 2048)
    (qbits ,(lambda (x) (member x '(160 256))) "(or/c 160 256)"  #:opt #f)))

(define config:dh-paramgen
  `((nbits     ,exact-positive-integer? #f                  #:opt 2048)
    (generator ,(lambda (x) (member x '(2 5))) "(or/c 2 5)" #:opt 2)))

(define config:ec-paramgen
  `((curve ,(lambda (x) (or (symbol? x) (string? x))) "(or/c symbol? string?)" #:req)))

(define config:eddsa-keygen
  `((curve ,(lambda (x) (memq x '(ed25519 ed448))) "(or/c 'ed25519 'ed448)" #:req)))

(define config:ecx-keygen
  `((curve ,(lambda (x) (memq x '(x25519 x448))) "(or/c 'x25519 'x448)" #:req)))

;; ============================================================
;; Security strength levels

;; Reference:
;; - NIST SP-800-57 Part 1 Section 5.6: Guidance for Cryptographic Algorithm and Key-Size...
;;   (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

;; Strength ratings: 0, 80, 112, 128, 192, 256

(define (rsa-security-bits nbits)
  (cond [(>= nbits 15360) 256]
        [(>= nbits 7680) 192]
        [(>= nbits 3072) 128]
        [(>= nbits 2048) 112]
        [(>= nbits 1024) 80]
        [else 0]))

(define (dsa/dh-security-bits nbits [qbits +inf.0])
  (cond [(and (>= nbits 3072) (>= qbits 256)) 128]
        [(and (>= nbits 2048) (>= qbits 224)) 112]
        [(and (>= nbits 1024) (>= qbits 160)) 80]
        [else 0]))

(define (ec-security-bits nbits)
  (cond [(>= nbits 512) 256]
        [(>= nbits 384) 192]
        [(>= nbits 256) 128]
        [(>= nbits 224) 112]
        [(>= nbits 160) 80]
        [else 0]))

(define (curve-security-bits curve)
  (define (ec n) (ec-security-bits n))
  (case (alias->curve-name curve)
    [(ed25519 x25519) (ec 255)]
    [(ed448 x448) (ec 448)]
    ;; -- Prime-order fields --
    [(secp192k1 secp192r1) (ec 192)]
    [(secp224k1 secp224r1) (ec 224)]
    [(secp256k1 secp256r1) (ec 256)]
    [(secp384r1) (ec 384)]
    [(secp521r1) (ec 521)]
    ;; -- Characteristic 2 fields --
    [(sect163k1 sect163r1) (ec 163)]
    [(sect163r2 sect233k1) (ec 163)]
    [(sect233r1) (ec 233)]
    [(sect239k1) (ec 239)]
    [(sect283k1 sect283r1) (ec 283)]
    [(sect409k1 sect409r1) (ec 409)]
    [(sect571k1 sect571r1) (ec 571)]
    ;; --
    [else #f]))

;; convert to used parsed/internal representation
(define (rkt-params-security-bits params)
  (match params
    [(list 'dsa p q g) (dsa/dh-security-bits (add1 (log p 2)) (add1 (log q 2)))]
    [(list* 'dh 'params p _) (dsa/dh-security-bits (add1 (log p 2)))]
    [(list 'ec 'params curve-oid)
     (curve-security-bits (curve-oid->name curve-oid))]
    [(list 'eddsa 'params curve) (curve-security-bits curve)]
    [(list 'ecx 'params curve) (curve-security-bits curve)]
    [else #f]))

(define (parsed-pkey-security-bits pkey)
  (match pkey
    [(list 'PUBLIC 'rsa n e)
     (let ([nbits (integer-length n)])
       (cond [(>= nbits 15360) 256]
             [(>= nbits 7680) 192]
             [(>= nbits 3072) 128]
             [(>= nbits 2048) 112]
             [(>= nbits 1024) 80]
             [else #f]))]
    [_ #f]))
