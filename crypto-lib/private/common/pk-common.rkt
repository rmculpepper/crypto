;; Copyright 2013-2022 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
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
         (all-from-out "pk-format.rkt"))

;; ============================================================
;; Base classes

(define pk-impl-base%
  (class* impl-base% (pk-impl<%>)
    (inherit about get-spec get-factory)
    (super-new)

    (define/override (to-write-string prefix)
      (super to-write-string (or prefix "pk:")))

    (define/public (generate-key config)
      (cond [(has-params?)
             (define p (generate-params config))
             (send p generate-key '())]
            [else (err/no-impl this)]))
    (define/public (generate-params config)
      (cond [(has-params?) (err/no-impl this)]
            [else (crypto-error "key parameters not supported\n  algorithm: ~a" (about))]))

    ;; can-encrypt? : Padding -> Boolean; pad=#f means "at all?"
    (define/public (can-encrypt? pad) #f)

    ;; can-sign : Pad -> Result; pad=#f means "at all?"
    ;; Result = #f        -- not supported (eg DH)
    ;;        | 'depends  -- call can-sign2? to check specific digest arg (eg RSA)
    ;;        | 'nodigest -- supported, but digest must be 'none (eg EdDSA)
    ;;        | 'ignoredg -- supported, digest arg ignored (eg DSA, EC, for backwards-compat)
    ;; For backwards compat, want to ignore digest arg for DSA and EC; but want to forbid
    ;; for EdDSA, so that in the future giving a digest argument can mean use EdDSAph.
    (define/public (can-sign pad) #f)

    ;; can-sign2? : Pad (U DigestSpec 'none) -> Boolean
    ;; Only overridden if can-sign returned 'depends.
    (define/public (can-sign2? pad dspec) #t)

    (define/public (can-key-agree?) #f)
    (define/public (has-params?) #f)

    ;; Called by pk-read-key%; signature depends on spec
    (define/public (make-params . _) #f)
    (define/public (make-public-key . _) #f)
    (define/public (make-private-key . _) #f)

    ;; Called by pk-{dsa,dh,ec}-params% generate-key:
    ;; - generate-key-from-params : PK-Params -> PK-Key

    ;; Called by pk-{eddsa,ecx}-params% generate-key:
    ;; - generate-key-from-curve : Symbol -> PK-Key
    ))

(define pk-params-base%
  (class* ctx-base% (pk-params<%>)
    (inherit-field impl)
    (super-new)
    (define/override (about) (format "~a parameters" (send impl about)))
    (define/override (to-write-string prefix)
      (string-append
       (super to-write-string (or prefix "pk-parameters:"))
       (cond [(is-a? this pk-curve-params<%>)
              (format ":~a" (send this get-curve))]
             [else ""])))

    (abstract generate-key) ;; Config -> PK-Key

    (define/public (write-params fmt)
      (or (-write-params fmt)
          (crypto-error "parameters format not supported\n  format: ~e\n  parameters: ~a"
                        fmt (about))))
    (define/public (-write-params fmt) #f)

    (define/public (get-security-bits)
      (rkt-params-security-bits (-write-params 'rkt-params)))
    ))

(define pk-key-base%
  (class* ctx-base% (pk-key<%>)
    (inherit-field impl)
    (super-new)

    (define/override (about)
      (format "~a ~a key" (send impl about) (if (is-private?) 'private 'public)))
    (define/override (to-write-string prefix)
      (string-append
       (super to-write-string (or prefix (if (is-private?) "private-key:" "public-key:")))
       (cond [(send impl has-params?)
              (define params (get-params))
              (cond [(is-a? params pk-curve-params<%>)
                     (format ":~s" (send params get-curve))]
                    [else ""])]
             [else ""])))
    (define/public (get-spec) (send impl get-spec))

    (define/public (get-security-bits)
      (if (send impl has-params?)
          (send (get-params) get-security-bits)
          #f))

    (abstract is-private?)
    (abstract get-public-key)
    (abstract equal-to-key?)

    (define/public (get-params)
      (if (send impl has-params?)
          (err/no-impl this)
          (crypto-error "key parameters not supported\n  key: ~a" (about))))

    (define/public (write-key fmt)
      (or (-write-key fmt)
          (crypto-error "key format not supported\n  format: ~e\n  key: ~a"
                        fmt (about))))
    (define/public (-write-key fmt) #f)

    ;; ----

    (define/public (sign msg dspec0 pad)
      (define dspec (or dspec0 'none))
      (-check-sign pad dspec)
      (unless (is-private?)
        (crypto-error "signing requires private key\n  key: ~a" (about)))
      (unless (eq? dspec 'none) (-check-msg-size msg dspec))
      (-sign msg dspec pad))

    (define/public (verify msg dspec0 pad sig)
      (define dspec (or dspec0 'none))
      (-check-sign pad dspec)
      (unless (eq? dspec 'none) (-check-msg-size msg dspec))
      (-verify msg dspec pad sig))

    (define/private (-check-sign pad dspec)
      (case (send impl can-sign pad)
        [(#f)
         (unless (send impl can-sign #f)
           (crypto-error "sign/verify not supported\n  key: ~a" (about)))
         (crypto-error "sign/verify padding not supported\n  padding: ~e\n  key: ~a"
                       pad (about))]
        [(depends)
         (unless (send impl can-sign2? pad dspec)
           (crypto-error "sign/verify options not supported\n  padding: ~e\n  digest: ~e\n  key: ~a"
                         pad dspec (about)))]
        [(nodigest)
         (unless (memq dspec '(none))
           (crypto-error "sign/verify digest not supported\n  digest: ~e\n  key: ~a"
                         dspec (about)))]
        [else (void)]))

    (define/private (-check-msg-size msg dspec)
      (check-bytes-length "digest" (digest-spec-size dspec) msg
                          #:fmt "\n  digest: ~e" #:args dspec))

    (define/public (-sign msg dspec pad) (err/no-impl this))
    (define/public (-verify msg dspec pad sig) (err/no-impl this))

    ;; ----

    (define/public (encrypt buf pad)
      (-check-encrypt pad)
      (-encrypt buf pad))
    (define/public (decrypt buf pad)
      (-check-encrypt pad)
      (unless (is-private?)
        (crypto-error "decryption requires private key\n  key: ~a" (about)))
      (-decrypt buf pad))

    (define/public (compute-secret peer-pubkey)
      (-check-key-agree)
      (let ([peer-pubkey
             (cond [(pk-key? peer-pubkey) peer-pubkey]
                   [else (-convert-for-key-agree peer-pubkey)])])
        (unless (pk-key? peer-pubkey)
          (internal-error "failed to convert peer key"))
        (let ([peer-pubkey
               (cond [(eq? (send peer-pubkey get-impl) impl) peer-pubkey]
                     [else ;; public key from different impl, must convert
                      (define (bad)
                        (crypto-error "~a~a\n  peer: ~a\n  key: ~a"
                                      "peer key has different implementation"
                                      ";\n and conversion to this implementation failed"
                                      (send peer-pubkey about) (about)))
                      (define peer-pub (or (send peer-pubkey -write-key 'rkt-public) (bad)))
                      (define peer-pubkey*
                        (let* ([factory (send impl get-factory)]
                               [reader (send factory get-pk-reader)])
                          (or (send reader read-key peer-pub 'rkt-public) (bad))))
                      (unless (eq? (send peer-pubkey* get-impl) impl) (bad))
                      peer-pubkey*])])
          (unless (-compatible-for-key-agree? peer-pubkey)
            (crypto-error "peer key is not compatible\n  peer: ~a\n  key: ~a"
                          (send peer-pubkey about) (about)))
          (-compute-secret peer-pubkey))))

    (define/public (-compatible-for-key-agree? peer-pubkey)
      ;; PRE: peer-pubkey is key with same impl as this
      (err/no-impl this))

    (define/public (-convert-for-key-agree bs)
      (crypto-error "cannot convert peer public key\n  key: ~a" (about)))

    (define/private (-check-encrypt pad)
      (unless (send impl can-encrypt? #f)
        (crypto-error "encrypt/decrypt not supported\n  key: ~a" (about)))
      (unless (send impl can-encrypt? pad)
        (crypto-error "encrypt/decrypt not supported\n  padding: ~e\n  key: ~a"
                      pad (about))))

    (define/public (-encrypt buf pad) (err/no-impl this))
    (define/public (-decrypt buf pad) (err/no-impl this))

    ;; ----

    (define/private (-check-key-agree)
      (unless (send impl can-key-agree?)
        (crypto-error "key agreement not supported\n  key: ~a" (about))))

    (define/public (-compute-secret peer-pubkey)
      ;; PRE: peer-pubkey is either pk w/ same impl, or not pk (eg, bytes)
      (err/no-impl this))
    ))

;; ============================================================

(define pk-dsa-params%
  (class* pk-params-base% ()
    (inherit-field impl)
    (super-new)

    (abstract get-param-values) ;; -> (values Nat Nat Nat)

    (define/override (-write-params fmt)
      (define-values (p q g) (get-param-values))
      (encode-params-dsa fmt p q g))

    (define/override (generate-key config)
      (check-config config '() "DSA keygen from parameters")
      (send impl generate-key-from-params this))
    ))

(define pk-dh-params%
  (class* pk-params-base% ()
    (inherit-field impl)
    (super-new)

    (abstract get-param-values) ;; -> (values Nat Nat Nat/#f Nat/#f Bytes/#f Nat/#f)

    (define/override (-write-params fmt)
      (define-values (p g q j seed pgen) (get-param-values))
      (encode-params-dh fmt p g q j seed pgen))

    (define/override (generate-key config)
      (check-config config '() "DH keygen from parameters")
      (send impl generate-key-from-params this))
    ))

(define pk-ec-params%
  (class* pk-params-base% (pk-curve-params<%>)
    (inherit-field impl)
    (super-new)

    (abstract get-curve)

    (define/public (get-curve-oid)
      (curve-alias->oid (get-curve)))

    (define/override (-write-params fmt)
      (define curve-oid (get-curve-oid))
      (and curve-oid (encode-params-ec fmt curve-oid)))

    (define/override (generate-key config)
      (check-config config '() "EC keygen")
      (send impl generate-key-from-params this))
    ))

(define pk-eddsa-params%
  (class* pk-params-base% (pk-curve-params<%>)
    (inherit-field impl)
    (init-field curve)
    (super-new)

    (define/public (get-curve) curve)

    (define/override (-write-params fmt)
      (encode-params-eddsa fmt curve))

    (define/override (generate-key config)
      (check-config config '() "EdDSA keygen")
      (send impl generate-key-from-curve curve))
    ))

(define pk-ecx-params%
  (class* pk-params-base% (pk-curve-params<%>)
    (inherit-field impl)
    (init-field curve)
    (super-new)

    (define/public (get-curve) curve)

    (define/override (-write-params fmt)
      (encode-params-ecx fmt curve))

    (define/override (generate-key config)
      (check-config config '() "EC/X key generation")
      (send impl generate-key-from-curve curve))
    ))

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

(define (rkt-params-security-bits params)
  (match params
    [(list 'dsa p q g) (dsa/dh-security-bits (add1 (log p 2)) (add1 (log q 2)))]
    [(list* 'dh 'params p _) (dsa/dh-security-bits (add1 (log p 2)))]
    [(list 'ec 'params curve-oid)
     (curve-security-bits (curve-oid->name curve-oid))]
    [(list 'eddsa 'params curve) (curve-security-bits curve)]
    [(list 'ecx 'params curve) (curve-security-bits curve)]
    [else #f]))
