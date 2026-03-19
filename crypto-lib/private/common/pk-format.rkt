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
         "../../util/bech32.rkt")
(provide (all-defined-out)
         curve-name->oid
         curve-alias->oid
         curve-oid->name)

;; ============================================================
;; Reading Keys

;; To avoid shared refs to mutable data:
;; - read-key makes a copy of bytestrings before forwarding them to implementations
;; - encode-*-* with 'rkt-* fmt makes a copy of bytestrings in arguments
;;   (but only for arguments where bytestring are expected)

(define pk-read-key-base%
  (class* impl-base% (pk-read-key<%>)
    (inherit-field factory)
    (super-new)

    (define/public (read-key sk fmt)
      (case fmt
        [(SubjectPublicKeyInfo)
         (-check-bytes fmt sk)
         (match (bytes->asn1/DER SubjectPublicKeyInfo sk)
           ;; Note: decode w/ type checks some well-formedness properties
           [(h-subject-public-key-info alg subjectPublicKey)
            (match-define (h-algorithm-identifier alg-oid params) alg)
            (cond [(equal? alg-oid rsaEncryption)
                   (-decode-pub-rsa subjectPublicKey)]
                  [(equal? alg-oid id-dsa)
                   (-decode-pub-dsa params subjectPublicKey)]
                  [(equal? alg-oid dhpublicnumber)
                   (-decode-pub-dh params subjectPublicKey)]
                  [(equal? alg-oid dhKeyAgreement)
                   (-decode-pub-dh params subjectPublicKey)]
                  [(equal? alg-oid id-ecPublicKey)
                   (-decode-pub-ec params subjectPublicKey)]
                  [(equal? alg-oid id-Ed25519)
                   (-decode-pub-eddsa 'ed25519 subjectPublicKey)]
                  [(equal? alg-oid id-Ed448)
                   (-decode-pub-eddsa 'ed448 subjectPublicKey)]
                  [(equal? alg-oid id-X25519)
                   (-decode-pub-ecx 'x25519 subjectPublicKey)]
                  [(equal? alg-oid id-X448)
                   (-decode-pub-ecx 'x448 subjectPublicKey)]
                  [else #f])]
           [_ #f])]
        [(PrivateKeyInfo OneAsymmetricKey)
         (-check-bytes fmt sk)
         (define (decode version alg privateKey publicKey)
           (match-define (h-algorithm-identifier alg-oid alg-params) alg)
           (cond [(equal? alg-oid rsaEncryption)
                  (-decode-priv-rsa privateKey)]
                 [(equal? alg-oid id-dsa)
                  (-decode-priv-dsa alg-params publicKey privateKey)]
                 [(equal? alg-oid dhpublicnumber)
                  (-decode-priv-dh alg-params publicKey privateKey)]
                 [(equal? alg-oid dhKeyAgreement)
                  (-decode-priv-dh alg-params publicKey privateKey)]
                 [(equal? alg-oid id-ecPublicKey)
                  (-decode-priv-ec alg-params publicKey privateKey)]
                 [(equal? alg-oid id-Ed25519)
                  (-decode-priv-eddsa 'ed25519 publicKey privateKey)]
                 [(equal? alg-oid id-Ed448)
                  (-decode-priv-eddsa 'ed448 publicKey privateKey)]
                 [(equal? alg-oid id-X25519)
                  (-decode-priv-ecx 'x25519 publicKey privateKey)]
                 [(equal? alg-oid id-X448)
                  (-decode-priv-ecx 'x448 publicKey privateKey)]
                 [else #f]))
         (case fmt
           ;; Avoid attempting to parse the publicKey field (which could fail!)
           ;; unless OneAsymmetricKey is requested.
           [(PrivateKeyInfo)
            (match (bytes->asn1/DER PrivateKeyInfo sk)
              [(h-private-key-info version alg privateKey)
               (decode version alg privateKey #f)]
              [_ #f])]
           [(OneAsymmetricKey)
            (match (bytes->asn1/DER OneAsymmetricKey sk)
              [(h-one-asymmetric-key version alg privateKey publicKey)
               (decode version alg privateKey publicKey)]
              [_ #f])])]
        [(RSAPrivateKey)
         (-check-bytes fmt sk)
         (-decode-priv-rsa (bytes->asn1/DER RSAPrivateKey sk))]
        [(DSAPrivateKey)
         (-check-bytes fmt sk)
         (match (bytes->asn1/DER (SEQUENCE-OF INTEGER) sk)
           [(list 0 p q g y x) ;; FIXME!
            (-make-priv-dsa p q g y x)])]
        [(rkt-private) (read-rkt-private-key sk)]
        [(rkt-public) (read-rkt-public-key sk)]
        [(age/v1-private)
         (-check-type fmt 'bech32-string? bech32-string? sk)
         (match (bech32-decode sk)
           [(list "age-secret-key-" priv)
            (-decode-priv-ecx 'x25519 #f priv)]
           [_ #f])]
        [(age/v1-public)
         (-check-type fmt 'bech32-string? bech32-string? sk)
         (match (bech32-decode sk)
           [(list "age" pub)
            (-decode-pub-ecx 'x25519 pub)]
           [_ #f])]
        [(openssh-public)
         (-check-type fmt 'string? string? sk)
         (match (parse-openssh-pub sk)
           [(list 'rsa e n)
            (-make-pub-rsa n e)]
           [(list 'ed25519 pub)
            (-decode-pub-eddsa 'ed25519 pub)]
           [(list 'ed448 pub)
            (-decode-pub-eddsa 'ed448 pub)]
           [_ #f])]
        [else #f]))

    (define/private (read-rkt-public-key sk)
      (define nat? exact-nonnegative-integer?)
      (define (nat/f? x) (or (nat? x) (eq? x #f)))
      (define (bytes/f? x) (or (bytes? x) (eq? x #f)))
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match sk
        [(list 'rsa 'public (? nat? n) (? nat? e))
         (-make-pub-rsa n e)]
        [(list 'dsa 'public (? nat? p) (? nat? q) (? nat? g) (? nat? y))
         (-make-pub-dsa p q g y)]
        [(list 'dh 'public (? nat? p) (? nat? g)
               (? nat? q) (? nat/f? j) (? bytes/f? seed) (? nat/f? pgen)
               (? nat? y))
         (-make-pub-dh p g q j (bcopy seed) pgen y)]
        [(list 'dh 'public (? nat? p) (? nat? g) (? nat? y))
         (-make-pub-dh p g #f #f #f #f y)]
        [(list 'ec 'public (? oid? curve-oid) (? bytes? qB))
         (-make-pub-ec curve-oid (bcopy qB))]
        [(list 'eddsa 'public curve (? bytes? qB))
         (-make-pub-eddsa curve (bcopy qB))]
        [(list 'ecx 'public curve (? bytes? qB))
         (-make-pub-ecx curve (bcopy qB))]
        [_ #f]))

    (define/private (read-rkt-private-key sk)
      (define nat? exact-nonnegative-integer?)
      (define (nat/f? x) (or (nat? x) (eq? x #f)))
      (define (bytes/f? x) (or (bytes? x) (eq? x #f)))
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match sk
        [(list 'rsa 'private 0 (? nat? n) (? nat? e) (? nat? d)
               (? nat? p) (? nat? q) (? nat? dp) (? nat? dq) (? nat? qInv))
         (-make-priv-rsa n e d p q dp dq qInv)]
        [(list 'dsa 'private (? nat? p) (? nat? q) (? nat? g) (? nat/f? y) (? nat? x))
         (let ([y (or y (dsa/dh-recompute-y p g x))])
           (-make-priv-dsa p q g y x))]
        [(list 'dh 'private (? nat? p) (? nat? g)
               (? nat? q) (? nat/f? j) (? bytes/f? seed) (? nat/f? pgen)
               (? nat/f? y) (? nat? x))
         (let ([y (or y (dsa/dh-recompute-y p g x))])
           (-make-priv-dh p g q j (bcopy seed) pgen y x))]
        [(list 'dh 'private (? nat? p) (? nat? g) (? nat/f? y) (? nat? x))
         (let ([y (or y (dsa/dh-recompute-y p g x))])
           (-make-priv-dh p g #f #f #f #f y x))]
        [(list 'ec 'private (? oid? curve-oid) (? bytes/f? qB) (? nat? x))
         (-make-priv-ec curve-oid (bcopy qB) x)]
        [(list 'eddsa 'private (? symbol? curve) (? bytes/f? qB) (? bytes? dB))
         (-make-priv-eddsa curve (bcopy qB) (bcopy dB))]
        [(list 'ecx 'private (? symbol? curve) (? bytes/f? qB) (? bytes? dB))
         (-make-priv-ecx curve (bcopy qB) (bcopy dB))]
        [_ #f]))

    (define-syntax-rule (send-to-impl spec method arg ...)
      (let ([impl (send factory get-pk spec)])
        (and impl (send impl method arg ...))))

    ;; ---- RSA ----

    (define/public (-decode-pub-rsa subjectPublicKey)
      (match subjectPublicKey
        [(h-rsa-public-key n e)
         (-make-pub-rsa n e)]))

    (define/public (-decode-priv-rsa privateKey)
      (match privateKey
        ;; support only two-prime keys (version = 0, otherPrimeInfos absent)
        [(h-rsa-private-key 0 n e d p q dp dq qInv)
         (-make-priv-rsa n e d p q dp dq qInv)]))

    (define/public (-make-pub-rsa n e)
      (send-to-impl 'rsa make-public-key n e))
    (define/public (-make-priv-rsa n e d p q dp dq qInv)
      (send-to-impl 'rsa make-private-key n e d p q dp dq qInv))

    ;; ---- DSA ----

    (define/public (-decode-pub-dsa params y)
      (match params
        [(h-dss-parms p q g)
         (-make-pub-dsa p q g y)]))

    (define/public (-decode-priv-dsa params y x)
      (match params
        [(h-dss-parms p q g)
         (let ([y (or y (dsa/dh-recompute-y p g x))])
           (-make-priv-dsa p q g y x))]))

    (define/public (-make-pub-dsa p q g y)
      (send-to-impl 'dsa make-public-key p q g y))
    (define/public (-make-priv-dsa p q g y x)
      (send-to-impl 'dsa make-private-key p q g y x))

    ;; ---- DH ----

    (define/public (-decode-pub-dh params y)
      (define-values (p g q j seed pgen) (get-dh-fields params))
      (-make-pub-dh p g q j seed pgen y))

    (define/public (-decode-priv-dh params y x)
      (define-values (p g q j seed pgen) (get-dh-fields params))
      (let ([y (or y (dsa/dh-recompute-y p g x))])
        (-make-priv-dh p g q j seed pgen y x)))

    (define/public (-make-pub-dh p g q j seed pgen y)
      (send-to-impl 'dh make-public-key p g q j seed pgen y))
    (define/public (-make-priv-dh p g q j seed pgen y x)
      (send-to-impl 'dh make-private-key p g q j seed pgen y x))

    (define/private (get-dh-fields params)
      (match params
        [(h-domain-parameters p g q j vp)
         (match vp
           ;; If seed is not octet-aligned, just drop it (and pgen).
           [(h-validation-parms seed pgen)
            #:when (and (bit-string? seed) (zero? (bit-string-unused seed)))
            (values p g q j (bit-string-bytes seed) pgen)]
           [#f
            (values p g q j #f #f)])]
        [(h-dhparameter p g)
         (values p g #f #f #f #f)]))

    ;; ---- EC ----

    (define/public (-decode-pub-ec params subjectPublicKey)
      (match params
        [`(namedCurve ,curve-oid)
         (-make-pub-ec curve-oid subjectPublicKey)]
        [_ #f]))

    (define/public (-decode-priv-ec params publicKey privateKey)
      (match params
        [`(namedCurve ,curve-oid)
         (match privateKey
           [(h-ec-private-key 1 xB qB)
            (-make-priv-ec curve-oid (or qB publicKey) (base256->unsigned xB))]
           [_ #f])]
        [_ #f]))

    (define/public (-make-pub-ec curve-oid qB)
      (send-to-impl 'ec make-public-key curve-oid qB))
    (define/public (-make-priv-ec curve-oid qB x)
      (send-to-impl 'ec make-private-key curve-oid qB x))

    ;; ---- EdDSA ----

    (define/public (-decode-pub-eddsa curve qB)
      (-make-pub-eddsa curve qB))
    (define/public (-decode-priv-eddsa curve qB dB)
      (-make-priv-eddsa curve qB dB))

    (define/public (-make-pub-eddsa curve qB)
      (send-to-impl 'eddsa make-public-key curve qB))
    (define/public (-make-priv-eddsa curve qB dB)
      (send-to-impl 'eddsa make-private-key curve qB dB))

    ;; ---- ECX ----

    (define/public (-decode-pub-ecx curve qB)
      (-make-pub-ecx curve qB))
    (define/public (-decode-priv-ecx curve qB dB)
      (-make-priv-ecx curve qB dB))

    (define/public (-make-pub-ecx curve qB)
      (send-to-impl 'ecx make-public-key curve qB))
    (define/public (-make-priv-ecx curve qB dB)
      (send-to-impl 'ecx make-private-key curve qB dB))

    ;; ----------------------------------------

    (define/public (read-params buf fmt)
      (case fmt
        [(AlgorithmIdentifier)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER AlgorithmIdentifier/DER buf)
           [(h-algorithm-identifier alg-oid parameters)
            (cond [(equal? alg-oid id-dsa)
                   (read-params parameters 'Dss-Parms)] ;; Dss-Parms
                  [(equal? alg-oid dhpublicnumber)
                   (read-params parameters 'DomainParameters)]
                  [(equal? alg-oid dhKeyAgreement)
                   (read-params parameters 'DHParameter)] ;; DHParameter
                  [(equal? alg-oid id-ecPublicKey)
                   (read-params parameters 'EcpkParameters)] ;; EcpkParameters
                  [(equal? alg-oid id-Ed25519) (-make-params-eddsa 'ed25519)]
                  [(equal? alg-oid id-Ed448)   (-make-params-eddsa 'ed448)]
                  [(equal? alg-oid id-X25519)  (-make-params-ecx   'x25519)]
                  [(equal? alg-oid id-X448)    (-make-params-ecx   'x448)]
                  [else #f])])]
        [(DSAParameters Dss-Parms)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER Dss-Parms buf)
           [(h-dss-parms p q g)
            (-make-params-dsa p q g)])]
        [(DomainParameters) ;; ANSI X9.42
         (-check-bytes fmt buf)
         (define-values (p g q j seed pgen)
           (get-dh-fields (bytes->asn1/DER DomainParameters buf)))
         (-make-params-dh p g q j seed pgen)]
        [(DHParameter) ;; PKCS#3
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER DHParameter buf)
           [(h-dhparameter p g)
            (-make-params-dh p g)])]
        [(EcpkParameters)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER EcpkParameters buf)
           [(list 'namedCurve curve-oid)
            (-make-params-ec curve-oid)]
           [_ #f])]
        [(rkt-params) (read-rkt-params buf)]
        [else #f]))

    (define/private (read-rkt-params p)
      (define nat? exact-nonnegative-integer?)
      (define (nat/f? x) (or (nat? x) (eq? x #f)))
      (define (bytes/f? x) (or (bytes? x) (eq? x #f)))
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match p
        [(list 'dsa 'params (? nat? p) (? nat? q) (? nat? g))
         (-make-params-dsa p q g)]
        [(list 'dh 'params (? nat? p) (? nat? g)
               (? nat? q) (? nat/f? j) (? bytes/f? seed) (? nat/f? pgen))
         (-make-params-dh p g q j (bcopy seed) pgen)]
        [(list 'dh 'params (? nat? p) (? nat? g))
         (-make-params-dh p g #f #f #f #f)]
        [(list 'ec 'params (? oid? curve-oid))
         (-make-params-ec curve-oid)]
        [(list 'eddsa 'params (? symbol? curve))
         (-make-params-eddsa curve)]
        [(list 'ecx 'params (? symbol? curve))
         (-make-params-ecx curve)]
        [_ #f]))

    (define/public (-make-params-dsa p q g)
      (send-to-impl 'dsa make-params p q g))
    (define/public (-make-params-dh p g q j seed pgen)
      (send-to-impl 'dh make-params p g q j seed pgen))
    (define/public (-make-params-ec curve-oid)
      (send-to-impl 'ec make-params curve-oid))
    (define/public (-make-params-eddsa curve)
      (send-to-impl 'eddsa make-params curve))
    (define/public (-make-params-ecx curve)
      (send-to-impl 'ecx make-params curve))

    ;; ----------------------------------------

    (define/private (-check-bytes fmt v)
      (-check-type fmt 'bytes? bytes? v))
    (define/private (-check-type fmt what pred v)
      (unless (pred v)
        (crypto-error "bad value for key format\n  expected: ~a\n  got: ~e\n  format: ~e"
                      what v fmt)))
    ))

(define translate-key%
  (class pk-read-key-base%
    (init-field fmt)
    (super-new (factory #f) (spec 'translate-key))
    (define/override (-make-pub-rsa n e)
      (encode-pub-rsa fmt n e))
    (define/override (-make-priv-rsa n e d p q dp dq qInv)
      (encode-priv-rsa fmt n e d p q dp dq qInv))
    (define/override (-make-params-dsa p q g)
      (encode-params-dsa fmt p q g))
    (define/override (-make-pub-dsa p q g y)
      (encode-pub-dsa fmt p q g y))
    (define/override (-make-priv-dsa p q g y x)
      (encode-priv-dsa fmt p q g y x))
    (define/override (-make-params-dh p g q j seed pgen)
      (encode-params-dh fmt p g q j seed pgen))
    (define/override (-make-pub-dh p g q j seed pgen y)
      (encode-pub-dh fmt p g q j seed pgen y))
    (define/override (-make-priv-dh p g q j seed pgen y x)
      (encode-priv-dh fmt p g q j seed pgen y x))
    (define/override (-make-params-ec curve-oid)
      (encode-params-ec fmt curve-oid))
    (define/override (-make-pub-ec curve-oid qB)
      (encode-pub-ec fmt curve-oid qB))
    (define/override (-make-priv-ec curve-oid qB x)
      (encode-priv-ec fmt curve-oid qB x))
    (define/override (-make-params-eddsa curve)
      (encode-params-eddsa fmt curve))
    (define/override (-make-pub-eddsa curve qB)
      (encode-pub-eddsa fmt curve qB))
    (define/override (-make-priv-eddsa curve qB dB)
      (encode-priv-eddsa fmt curve qB dB))
    (define/override (-make-params-ecx curve)
      (encode-params-ecx fmt curve))
    (define/override (-make-pub-ecx curve qB)
      (encode-pub-ecx fmt curve qB))
    (define/override (-make-priv-ecx curve qB dB)
      (encode-priv-ecx fmt curve qB dB))
    ))

;; translate-key : Datum KeyFormat KeyFormat -> (U Datum #f)
(define (translate-key key-datum from-fmt to-fmt)
  (send (new translate-key% (fmt to-fmt)) read-key key-datum from-fmt))

;; translate-params : Datum ParamsFormat ParamsFormat -> (U Datum #f)
(define (translate-params params-datum from-fmt to-fmt)
  (send (new translate-key% (fmt to-fmt)) read-params params-datum from-fmt))

;; bcopy : (U Bytes #f) -> (U Bytes #f)
;; Makes a fresh copy when given bytes.
(define (bcopy x) (if (bytes? x) (bytes-copy x) x))

;; check-recomputed-qB : Bytes (U Bytes #f) -> Void
(define (check-recomputed-qB new-qB maybe-old-qB)
  (when maybe-old-qB
    (unless (equal? new-qB maybe-old-qB)
      (crypto-error "public key does not match private key"))))

;; References (OpenSSH key format):
;; - https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/ (overview)
;; - RFC 4253 (https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
;; - RFC 8709 (for Ed{25519,448} keys)
(define (parse-openssh-pub s)
  (cond [(regexp-match #rx"^(ssh-rsa|ssh-ed25519|ssh-ed448) ([a-zA-Z0-9+/]+)(?: |$)" s)
         => (lambda (m) (parse-openssh-pub* (cadr m) (base64-decode (caddr m))))]
        [else (error 'wtf) #f]))
(define (parse-openssh-pub* outer-tag-s bin)
  (define (bad msg) (crypto-error "invalid key encoding~a" msg))
  (define binlen (bytes-length bin))
  (define (check-len n) (unless (<= n binlen) (bad " (index out of range)")))
  (define (get-uint4 n) (check-len (+ n 4)) (bytes->integer bin #f #t n (+ n 4)))
  (define (get-bstring n len) (check-len (+ n len)) (subbytes bin n (+ n len)))
  (define taglen (get-uint4 0))
  (define inner-tag (get-bstring 4 taglen))
  (unless (equal? (bytes->string/latin-1 inner-tag) outer-tag-s)
    (bad " (key type mismatch)"))
  (define keystart (+ 4 taglen))
  (case inner-tag
    [(#"ssh-rsa")
     (define elen (get-uint4 keystart))
     (define e (bytes->integer (get-bstring (+ keystart 4) elen) #t))
     (define nlen (get-uint4 (+ keystart 4 elen)))
     (define n (bytes->integer (get-bstring (+ keystart 4 elen 4) nlen) #t))
     (unless (= binlen (+ keystart 4 elen 4 nlen)) (bad " (bytes left over)"))
     (list 'rsa e n)]
    [(#"ssh-ed25519")
     (define publen (get-uint4 keystart))
     (define pub (get-bstring (+ keystart 4) publen))
     (unless (= publen 32) (bad " (wrong key length)"))
     (unless (= binlen (+ keystart 4 publen)) (bad " (bytes left over)"))
     (list 'ed25519 pub)]
    [(#"ssh-ed448")
     (define publen (get-uint4 keystart))
     (define pub (get-bstring (+ keystart 4) publen))
     (unless (= publen 57) (bad " (wrong key length)"))
     (unless (= binlen (+ keystart 4 publen)) (bad " (bytes left over)"))
     (list 'ed448 pub)]
    [else #f]))

;; write-openssh-pub : Bytes (U Bytes ExactInteger) ... -> String
(define (write-openssh-pub prefix . parts)
  (define (bstr bs)
    (bytes-append (integer->bytes (bytes-length bs) 4 #f) bs))
  (define (mpint n)
    (define nlen (integer-bytes-length n #t))
    (bytes-append (integer->bytes nlen 4 #f) (integer->bytes n nlen #t)))
  (define bin (apply bytes-append
                     (for/list ([part (in-list (cons prefix parts))])
                       (cond [(bytes? part) (bstr part)]
                             [(exact-integer? part) (mpint part)]))))
  (format "~a ~a" (base64-encode bin)))


;; ============================================================
;; Writing Keys

;; Only use OneAsymmetricKey format if public key supplied and
;; PrivateKeyInfo can't represent it.

;; On presence/absence of AlgorithmIdentifier parameters:
;; - CAB BR (v1.7.3) section 7.1.3 says for SPKI
;;   - NULL parameters must be present for RSA
;; - RFC 8410 says in general
;;   - for Ed25519 etc, parameters must be absent

;; ---- RSA ----

(define (encode-pub-rsa fmt n e)
  (case fmt
    [(SubjectPublicKeyInfo)
     ;; CAB BR (v1.7.3) section 7.1.3.1.1 says MUST include NULL parameter
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info
                       (h-algorithm-identifier rsaEncryption #f)
                       (h-rsa-public-key n e)))]
    [(rkt-public) (list 'rsa 'public n e)]
    [(openssh-public) (write-openssh-pub #"ssh-rsa" e n)]
    [else #f]))

(define (encode-priv-rsa fmt n e d p q dp dq qInv)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key fields, so just
     ;; produce PrivateKeyInfo syntax
     (asn1->bytes/DER
      PrivateKeyInfo
      (h-private-key-info 0
                          (h-algorithm-identifier rsaEncryption #f)
                          (h-rsa-private-key 0 n e d p q dp dq qInv)))]
    [(RSAPrivateKey)
     (asn1->bytes/DER RSAPrivateKey (h-rsa-private-key 0 n e d p q dp dq qInv))]
    [(rkt-private) (list 'rsa 'private 0 n e d p q dp dq qInv)]
    [else (encode-pub-rsa fmt n e)]))

;; ---- DSA ----

(define (dsa-algid p q g)
  (h-algorithm-identifier id-dsa (h-dss-parms p q g)))

(define (encode-params-dsa fmt p q g)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (dsa-algid p q g))]
    [(DSAParameters Dss-Parms)
     (asn1->bytes/DER Dss-Parms (h-dss-parms p q g))]
    [(rkt-params) (list 'dsa 'params p q g)]
    [else #f]))

(define (encode-pub-dsa fmt p q g y)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (dsa-algid p q g) y))]
    [(rkt-public) (list 'dsa 'public p q g y)]
    [else (encode-params-dsa fmt p q g)]))

(define (encode-priv-dsa fmt p q g y x)
  (let ([y (or y (dsa/dh-recompute-y p g x))])
    (case fmt
      [(PrivateKeyInfo)
       (asn1->bytes/DER PrivateKeyInfo
                        (h-private-key-info 0 (dsa-algid p q g) x))]
      [(OneAsymmetricKey)
       (asn1->bytes/DER OneAsymmetricKey
                        (h-one-asymmetric-key 1 (dsa-algid p q g) x y))]
      [(DSAPrivateKey)
       (asn1->bytes/DER
        (SEQUENCE-OF INTEGER)
        (list 0 p q g y x))]
      [(rkt-private) (list 'dsa 'private p q g y x)]
      [else (encode-pub-dsa fmt p q g y)])))

;; ---- DH ----

(define (dh-algid p g q j seed pgen)
  (if q
      (h-algorithm-identifier dhpublicnumber
                              (make-domain-parameters p g q j seed pgen))
      (h-algorithm-identifier dhKeyAgreement
                              (h-dhparameter p g))))

(define (make-domain-parameters p g q j seed pgen)
  (define vp (and (and seed pgen) (h-validation-parms (bit-string seed 0) pgen)))
  (h-domain-parameters p g q j vp))

(define (encode-params-dh fmt p g q j seed pgen)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (dh-algid p g q j seed pgen))]
    [(DomainParameters)
     (asn1->bytes/DER DomainParameters (make-domain-parameters p g q j seed pgen))]
    [(DHParameter)
     (asn1->bytes/DER DHParameter (h-dhparameter p g))]
    [(rkt-params)
     (cond [q (list 'dh 'params p g q j seed pgen)]
           [else (list 'dh 'params p g)])]
    [else #f]))

(define (encode-pub-dh fmt p g q j seed pgen y)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (dh-algid p g q j seed pgen) y))]
    [(rkt-public)
     (cond [q (list 'dh 'public p g q j seed pgen y)]
           [else (list 'dh 'public p g y)])]
    [else (encode-params-dh fmt p g q j seed pgen)]))

(define (encode-priv-dh fmt p g q j seed pgen y x)
  (let ([y (or y (dsa/dh-recompute-y p g x))])
    (case fmt
      [(PrivateKeyInfo)
       (asn1->bytes/DER PrivateKeyInfo
                        (h-private-key-info 0 (dh-algid p g q j seed pgen) x))]
      [(OneAsymmetricKey)
       (asn1->bytes/DER OneAsymmetricKey
                        (h-one-asymmetric-key 1 (dh-algid p g q j seed pgen) x y))]
      [(rkt-private)
       (cond [q (list 'dh 'private p g q j seed pgen y x)]
             [else (list 'dh 'private p g y x)])]
      [else (encode-pub-dh fmt p g q j seed pgen y)])))

;; ---- EC ----

(define (ec-algid curve-oid)
  (h-algorithm-identifier id-ecPublicKey (list 'namedCurve curve-oid)))

(define (encode-params-ec fmt curve-oid)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (ec-algid curve-oid))]
    [(EcpkParameters)
     (asn1->bytes/DER EcpkParameters (list 'namedCurve curve-oid))]
    [(rkt-params) (list 'ec 'params curve-oid)]
    [else #f]))

(define (encode-pub-ec fmt curve-oid qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (ec-algid curve-oid) qB))]
    [(rkt-public) (list 'ec 'public curve-oid (bcopy qB))]
    [else (encode-params-ec fmt curve-oid)]))

(define (encode-priv-ec fmt curve-oid qB d)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key, so just produce
     ;; PrivateKeyInfo syntax
     (asn1->bytes/DER
      PrivateKeyInfo
      (h-private-key-info 0 (ec-algid curve-oid)
                          (h-ec-private-key
                           ecPrivkeyVer1
                           (unsigned->base256 d)
                           qB)))]
    [(rkt-private) (list 'ec 'private curve-oid (bcopy qB) d)]
    [else (encode-pub-ec fmt curve-oid qB)]))

;; ---- EdDSA ----

(define (eddsa-algid curve)
  ;; RFC 8410 says parameters MUST be absent.
  (h-algorithm-identifier (ed-curve->oid curve) 'omit))

(define (encode-params-eddsa fmt curve)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (eddsa-algid curve))]
    [(rkt-params) (list 'eddsa 'params curve)]
    [else #f]))

(define (encode-pub-eddsa fmt curve qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (eddsa-algid curve) qB))]
    [(rkt-public) (list 'eddsa 'public curve (bcopy qB))]
    [(openssh-public)
     (case curve
       [(ed25519) (write-openssh-pub #"ssh-ed25519" qB)]
       [(ed448) (write-openssh-pub #"ssh-ed448" qB)]
       [else #f])]
    [else (encode-params-eddsa fmt curve)]))

(define (encode-priv-eddsa fmt curve qB dB)
  (case fmt
    [(PrivateKeyInfo)
     (asn1->bytes/DER PrivateKeyInfo
                      (h-private-key-info 0 (eddsa-algid curve) dB))]
    [(OneAsymmetricKey)
     (asn1->bytes/DER OneAsymmetricKey
                      (h-one-asymmetric-key 1 (eddsa-algid curve) dB qB))]
    [(rkt-private) (list 'eddsa 'private curve (bcopy qB) (bcopy dB))]
    [else (encode-pub-eddsa fmt curve qB)]))

(define (ed-curve->oid curve)
  (case curve
    [(ed25519) id-Ed25519]
    [(ed448)   id-Ed448]))

;; ---- ECX ----

(define (ecx-algid curve)
  ;; RFC 8410 says parameters MUST be absent.
  (h-algorithm-identifier (x-curve->oid curve)))

(define (encode-params-ecx fmt curve)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (ecx-algid curve))]
    [(rkt-params) (list 'ecx 'params curve)]
    [else #f]))

(define (encode-pub-ecx fmt curve qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (ecx-algid curve) qB))]
    [(rkt-public) (list 'ecx 'public curve (bcopy qB))]
    [(age/v1-public)
     (and (eq? curve 'x25519)
          (bech32-encode "age" qB))]
    [else (encode-params-ecx fmt curve)]))

(define (encode-priv-ecx fmt curve qB dB)
  (case fmt
    [(PrivateKeyInfo)
     (asn1->bytes/DER PrivateKeyInfo
                      (h-private-key-info 0 (ecx-algid curve) dB))]
    [(OneAsymmetricKey)
     (asn1->bytes/DER OneAsymmetricKey
                      (h-one-asymmetric-key 0 (ecx-algid curve) dB qB))]
    [(rkt-private)
     (list 'ecx 'private curve (bcopy qB) (bcopy dB))]
    [(age/v1-private)
     (and (eq? curve 'x25519)
          (string-upcase (bech32-encode "age-secret-key-" dB)))]
    [else (encode-pub-ecx fmt curve qB)]))

(define (x-curve->oid curve)
  (case curve
    [(x25519) id-X25519]
    [(x448)   id-X448]))

;; ============================================================

(define (dsa/dh-recompute-y p g x)
  ;; y = g^x mod p
  (mod-expt g x p))

(define (mod-expt n e p)
  ;; compute (n^e) mod p, using ladder
  (define (modp n) (modulo n p))
  (let loop ([n n] [e e])
    (cond [(zero? e) 1]
          [(even? e) (loop (modp (* n n)) (quotient e 2))]
          [else (modp (* n (loop n (sub1 e))))])))

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

;; curve-alias->oid : Symbol/String -> OID/#f
(define (curve-alias->oid alias)
  (curve-name->oid (alias->curve-name alias)))

;; ============================================================

;; Reference: https://datatracker.ietf.org/doc/html/rfc7748, Section 5

;; Check if bytestring has the proper form of X{25519,448} secret key.
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

;; Modify bytestring to have the proper form of X{25519,448} secret key.
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
