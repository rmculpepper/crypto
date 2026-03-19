;; Copyright 2013-2026 Ryan Culpepper
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
         curve-alias->oid)

;; Conventions:
;; - `parse-X` takes user data (bytes, usually)
;; - `decode-X` takes "ASNValue" -- parsed ASN.1 (result of bytes->asn1/DER)
;;   - can rely on well-formed ASN.1 representation types

;; ParseResult = (list (U 'params 'public 'private) PKSpec Any ...)
(define (ok-params pkspec . vs) (list* 'params pkspec vs))
(define (ok-public pkspec . vs) (list* 'public pkspec vs))
(define (ok-private pkspec . vs) (list* 'private pkspec vs))
(define (err/fmt fmt [why ""])
  (crypto-error "invalid key datum~a\n  format: ~e" why fmt))


;; ============================================================
;; Parsing Parameters

;; parse-params : Symbol Datum -> ParseResult
(define (parse-params fmt buf)
  (case fmt
    [(AlgorithmIdentifier)
     (-check-bytes fmt buf)
     (parse-AlgorithmIdentifier buf)]
    [(DSAParameters Dss-Parms)
     (-check-bytes fmt buf)
     (decode-DSAParameters (bytes->asn1/DER Dss-Parms buf))]
    [(DomainParameters) ;; ANSI X9.42
     (-check-bytes fmt buf)
     (decode-DomainParameters (bytes->asn1/DER DomainParameters buf))]
    [(DHParameter) ;; PKCS#3
     (-check-bytes fmt buf)
     (decode-DHParameter (bytes->asn1/DER DHParameter buf))]
    [(EcpkParameters)
     (-check-bytes fmt buf)
     (decode-EcpkParameters (bytes->asn1/DER EcpkParameters buf))]
    [(rkt-params) (read-rkt-params buf)]
    [else (crypto-error "unknown parameters format\n  format: ~e" fmt)]))

(define (parse-AlgorithmIdentifier buf)
  (decode-AlgorithmIdentifier
   (bytes->asn1/DER AlgorithmIdentifier buf)))
(define (decode-AlgorithmIdentifier ast)
  (match ast
    [(h-algorithm-identifier alg-oid params)
     (cond [(equal? alg-oid id-dsa)
            (decode-DSAParameters params)]
           [(equal? alg-oid dhpublicnumber)
            (decode-DomainParameters params)]
           [(equal? alg-oid dhKeyAgreement)
            (decode-DHParameter params)]
           [(equal? alg-oid id-ecPublicKey)
            (decode-EcpkParameters params)]
           [(equal? alg-oid id-Ed25519) (ok-params 'eddsa 'ed25519)]
           [(equal? alg-oid id-Ed448)   (ok-params 'eddsa 'ed448)]
           [(equal? alg-oid id-X25519)  (ok-params 'ecx   'x25519)]
           [(equal? alg-oid id-X448)    (ok-params 'ecx   'x448)]
           [else #f])]))

(define (decode-DSAParameters params)
  (match params
    [(h-dss-parms p q g)
     (check-dsa p q g)
     (ok-params 'dsa p q g)]))

(define (decode-DomainParameters params)
  (define-values (p g q j seed pgen) (extract-dh-params params))
  (check-dh p g q j)
  (ok-params 'dh p g q j seed pgen))

(define (decode-DHParameter params)
  (define-values (p g q j seed pgen) (extract-dh-params params))
  ;; cannot check-dh without q
  (ok-params 'dh p g q j seed pgen))

(define (extract-dh-params params)
  (match params
    [(h-domain-parameters p g q j vp)
     (match vp
       ;; if seed is not octet-aligned, just drop it (and pgen)
       [(h-validation-parms seed pgen)
        #:when (and (bit-string? seed) (zero? (bit-string-unused seed)))
        (values p g q j (bit-string-bytes seed) pgen)]
       [#f
        (values p g q j #f #f)])]
    [(h-dhparameter p g)
     (values p g #f #f #f #f)]))

(define (decode-EcpkParameters params)
  (define curve-oid (extract-ec-params params))
  (ok-params 'ec curve-oid))

(define (extract-ec-params params)
  (match params
    [(list 'namedCurve curve-oid) curve-oid]
    [_ (crypto-error "unsupported EC parameters (expected named curve)")]))


;; ============================================================
;; Parsing Keys

;; parse-key : Symbol Datum -> ParseResult
(define (parse-key fmt sk)
  (case fmt
    [(rkt-private) (read-rkt-private-key sk)]
    [(rkt-public) (read-rkt-public-key sk)]
    [(SubjectPublicKeyInfo)
     (-check-bytes fmt sk)
     (parse-SubjectPublicKeyInfo sk)]
    [(PrivateKeyInfo OneAsymmetricKey)
     (-check-bytes fmt sk)
     (parse-PrivateKeyInfo sk)]
    [(RSAPrivateKey)
     (-check-bytes fmt sk)
     (decode-RSAPrivateKey (bytes->asn1/DER RSAPrivateKey sk))]
    [(DSAPrivateKey)
     (-check-bytes fmt sk)
     (match (bytes->asn1/DER (SEQUENCE-OF INTEGER) sk)
       [(list 0 p q g y x) ;; FIXME!
        (check-dsa p q g)
        (ok-private 'dsa p q g y x)]
       [_ (err/fmt fmt)])]
    [(age/v1-private)
     (-check-type fmt 'bech32-string? bech32-string? sk)
     (match (bech32-decode sk)
       [(list "age-secret-key-" priv)
        (ok-private 'ecx 'x25519 #f priv)]
       [_ (err/fmt fmt)])]
    [(age/v1-public)
     (-check-type fmt 'bech32-string? bech32-string? sk)
     (match (bech32-decode sk)
       [(list "age" pub)
        (ok-public 'ecx 'x25519 pub)]
       [_ (err/fmt fmt)])]
    [(openssh-public)
     (-check-type fmt 'string? string? sk)
     (match (parse-openssh-pub sk)
       [(list 'rsa e n)
        (ok-public 'rsa n e)]
       [(list 'ed25519 pub)
        (ok-public 'eddsa 'ed25519 pub)]
       [(list 'ed448 pub)
        (ok-public 'eddsa 'ed448 pub)]
       [_ (err/fmt fmt)])]
    [else (crypto-error "unknown key format\n  format: ~e" fmt)]))

;; decode-public-key : OID Params PublicKey -> ParseResult
(define (decode-public-key alg-oid alg-params publicKey)
  (cond [(equal? alg-oid rsaEncryption)
         (decode-RSAPublicKey publicKey)]
        [(equal? alg-oid id-dsa)
         (decode-DSAPublicKey alg-params publicKey)]
        [(equal? alg-oid dhpublicnumber)
         (decode-dh-public-key alg-params publicKey)]
        [(equal? alg-oid dhKeyAgreement)
         (decode-dh-public-key alg-params publicKey)]
        [(equal? alg-oid id-ecPublicKey)
         (decode-ec-public-key alg-params publicKey)]
        [(equal? alg-oid id-Ed25519)
         (ok-public 'eddsa 'ed25519 publicKey)]
        [(equal? alg-oid id-Ed448)
         (ok-public 'eddsa 'ed448 publicKey)]
        [(equal? alg-oid id-X25519)
         (ok-public 'ecx 'x25519 publicKey)]
        [(equal? alg-oid id-X448)
         (ok-public 'ecx 'x448 publicKey)]
        [else (crypto-error "unknown algorithm identifier\n  OID: ~e" alg-oid)]))

;; decode-private-key : OID Params PublicKey/#f PrivateKey -> ParseResult
(define (decode-private-key alg-oid alg-params publicKey privateKey)
  (cond [(equal? alg-oid rsaEncryption)
         (decode-RSAPrivateKey privateKey)]
        [(equal? alg-oid id-dsa)
         (decode-dsa-private-key alg-params publicKey privateKey)]
        [(equal? alg-oid dhpublicnumber)
         (decode-dh-private-key alg-params publicKey privateKey)]
        [(equal? alg-oid dhKeyAgreement)
         (decode-dh-private-key alg-params publicKey privateKey)]
        [(equal? alg-oid id-ecPublicKey)
         (decode-ec-private-key alg-params publicKey privateKey)]
        [(equal? alg-oid id-Ed25519)
         (ok-private 'eddsa 'ed25519 publicKey privateKey)]
        [(equal? alg-oid id-Ed448)
         (ok-private 'eddsa 'ed448 publicKey privateKey)]
        [(equal? alg-oid id-X25519)
         (ok-private 'ecx 'x25519 publicKey privateKey)]
        [(equal? alg-oid id-X448)
         (ok-private 'ecx 'x448 publicKey privateKey)]
        [else (crypto-error "unknown algorithm identifier\n  OID: ~e" alg-oid)]))

(define (parse-SubjectPublicKeyInfo sk)
  (decode-SubjectPublicKeyInfo (bytes->asn1/DER SubjectPublicKeyInfo sk)))
(define (decode-SubjectPublicKeyInfo spki)
  (match spki
    [(h-subject-public-key-info alg subjectPublicKey)
     (match alg
       [(h-algorithm-identifier alg-oid alg-params)
        (decode-public-key alg-oid alg-params subjectPublicKey)])]))

(define (parse-PrivateKeyInfo sk)
  ;; parse as OneAsymmetricKey (PrivateKeyInfo v2), also accepts v1
  (decode-PrivateKeyInfo (bytes->asn1/DER OneAsymmetricKey sk)))
(define (decode-PrivateKeyInfo pki)
  (match pki
    [(h-one-asymmetric-key version alg privateKey publicKey)
     (match alg
       [(h-algorithm-identifier alg-oid alg-params)
        (decode-private-key alg-oid alg-params publicKey privateKey)])]))

(define (decode-RSAPublicKey subjectPublicKey)
  (match subjectPublicKey
    [(h-rsa-public-key n e)
     (ok-public 'rsa n e)]))
(define (decode-RSAPrivateKey privateKey)
  (match privateKey
    ;; support only two-prime keys (version = 0, otherPrimeInfos absent)
    [(h-rsa-private-key 0 n e d p q dp dq qInv)
     (ok-private 'rsa n e d p q dp dq qInv)]))

(define (decode-DSAPublicKey params y)
  (match params
    [(h-dss-parms p q g)
     (check-dsa p q g)
     (ok-public 'dsa p q g y)]))
(define (decode-dsa-private-key params y x)
  (match params
    [(h-dss-parms p q g)
     (check-dsa p q g)
     (let ([y (or y (dsa/dh-recompute-y p g x))])
       (ok-private 'dsa p q g y x))]))

(define (decode-dh-public-key params y)
  (define-values (p g q j seed pgen) (extract-dh-params params))
  (check-dh p g q j)
  (ok-public 'dh p g q j seed pgen y))
(define (decode-dh-private-key params y x)
  (define-values (p g q j seed pgen) (extract-dh-params params))
  (check-dh p g q j)
  (let ([y (or y (dsa/dh-recompute-y p g x))])
    (ok-private 'dh p g q j seed pgen y x)))

(define (decode-ec-public-key params subjectPublicKey)
  (define curve-oid (extract-ec-params params))
  (ok-public 'ec curve-oid subjectPublicKey))
(define (decode-ec-private-key params publicKey privateKey)
  (define curve-oid (extract-ec-params params))
  (match privateKey
    [(h-ec-private-key 1 xB qB)
     (ok-private 'ec curve-oid (or qB publicKey) (base256->unsigned xB))]))

(define (decode-eddsa-public-key curve qB)
  (ok-public 'eddsa curve qB))
(define (decode-eddsa-private-key curve qB dB)
  (ok-public 'eddsa curve qB dB))

(define (decode-ecx-public-key curve qB)
  (ok-public 'ecx curve qB))
(define (-decode-priv-ecx curve qB dB)
  (ok-public 'ecx curve qB dB))


;; ============================================================
;; rkt-{params,public,private} formats

(define (read-rkt-params p)
  (match p
    [(list 'dsa 'params p q g)
     (tc-dsa p q g)
     (check-dsa p q g)
     (ok-params 'dsa p q g)]
    [(list 'dh 'params p g q j seed pgen)
     (tc-dh p g q j seed pgen)
     (check-dh p g q j)
     (ok-params 'dh p g q j (bcopy seed) pgen)]
    [(list 'dh 'params p g)
     (tc exact-positive-integer? #f '(p g) p g)
     (ok-params 'dh p g #f #f #f #f)]
    [(list 'ec 'params curve-oid)
     (tc oid? #f '(curve-oid) curve-oid)
     (ok-params 'ec curve-oid)]
    [(list 'eddsa 'params curve)
     (tc eddsa-curve? #f '(curve) curve)
     (ok-params 'eddsa curve)]
    [(list 'ecx 'params curve)
     (tc ecx-curve? #f '(curve) curve)
     (ok-params 'ecx curve)]
    [_ (err/fmt 'rkt-params)]))

(define (read-rkt-public-key sk)
  (match sk
    [(list 'rsa 'public n e)
     (tc exact-positive-integer? #f '(n e) n e)
     (ok-public 'rsa n e)]
    [(list 'dsa 'public p q g y)
     (tc-dsa p q g)
     (tc exact-positive-integer? #f '(y) y)
     (check-dsa p q g)
     (ok-public 'dsa p q g y)]
    [(list 'dh 'public p g q j seed pgen y)
     (tc-dh p g q j seed pgen)
     (tc exact-positive-integer? #f '(y) y)
     (check-dh p g q j)
     (ok-public 'dh p g q j (bcopy seed) pgen y)]
    [(list 'dh 'public p g y)
     (tc exact-positive-integer? #f '(p g y) p g y)
     ;; cannot check-dh witout q
     (ok-public 'dh p g #f #f #f #f y)]
    [(list 'ec 'public curve-oid Q)
     (tc oid? #f '(curve-oid) curve-oid)
     (tc-ec-point #f 'Q Q)
     (ok-public 'ec curve-oid (bcopy Q))]
    [(list 'eddsa 'public curve Q)
     (tc eddsa-curve? #f '(curve) curve)
     (tc bytes? #f '(Q) Q)
     (ok-public 'eddsa curve (bcopy Q))]
    [(list 'ecx 'public curve Q)
     (tc ecx-curve? #f '(curve) curve)
     (tc bytes? #f '(Q) Q)
     (ok-public 'ecx curve (bcopy Q))]
    [_ (err/fmt 'rkt-public)]))

(define (read-rkt-private-key sk)
  (match sk
    [(list 'rsa 'private 0 n e d p q dp dq qInv)
     (tc exact-positive-integer? #f '(n e d p q dp dq qInv) n e d p q dp dq qInv)
     (ok-private 'rsa n e d p q dp dq qInv)]
    [(list 'dsa 'private p q g y x)
     (tc exact-positive-integer? #f '(p q g x) p g g x)
     (tc exact-positive-integer? #t '(y) y)
     (check-dsa p q g)
     (let ([y (or y (dsa/dh-recompute-y p g x))])
       (ok-private 'dsa p q g y x))]
    [(list 'dh 'private p g q j seed pgen y x)
     (tc-dh p g q j seed pgen)
     (tc exact-positive-integer? #t '(y) y)
     (tc exact-positive-integer? #f '(x) x)
     (check-dh p g q j)
     (let ([y (or y (dsa/dh-recompute-y p g x))])
       (ok-private 'dh p g q j (bcopy seed) pgen y x))]
    [(list 'dh 'private p g y x)
     (tc exact-positive-integer? #f '(p g x) p g x)
     (tc exact-positive-integer? #t '(y) y)
     ;; cannot check-dh without q
     (let ([y (or y (dsa/dh-recompute-y p g x))])
       (ok-private 'dh p g #f #f #f #f y x))]
    [(list 'ec 'private curve-oid Q x)
     (tc oid? #f '(curve-oid) curve-oid)
     (tc-ec-point #f 'Q Q)
     (tc exact-positive-integer? #f '(x) x)
     (ok-private 'ec curve-oid (bcopy Q) x)]
    [(list 'eddsa 'private curve Q d)
     (tc eddsa-curve? #f '(curve) curve)
     (tc bytes? #t '(Q) Q)
     (tc bytes? #f '(d) d)
     (ok-private 'eddsa curve (bcopy Q) (bcopy d))]
    [(list 'ecx 'private curve Q d)
     (tc ecx-curve? #f '(curve) curve)
     (tc bytes? #t '(Q) Q)
     (tc bytes? #f '(d) d)
     (ok-private 'ecx curve (bcopy Q) (bcopy d))]
    [_ (err/fmt 'rkt-private)]))

;; Don't put value in error; potentially secret data.
(define (tc pred or-false? labels . vs)
  (for ([label (in-list labels)] [v (in-list vs)])
    (unless (or (pred v) (and or-false? (eq? v #f)))
      (crypto-error "invalid key datum (bad ~s value)" label))))

(define (tc-dsa p q g)
  (tc exact-positive-integer? #f '(p q g) p q g))

(define (tc-dh p g q j seed pgen)
  (tc exact-positive-integer? #f '(p g q) p g q)
  (tc exact-positive-integer? #t '(j) j)
  (tc bytes? #t '(seed) seed)
  (tc exact-nonnegative-integer? #t '(pgenCounter) pgen))

(define (tc-ec-point or-false? label v)
  (unless (or (ok-ec-point? v) (and or-false? (eq? v #f)))
    (crypto-error "invalid key datum (bad ~s EC point)" label)))

(define (oid? x) (and (list? x) (andmap exact-nonnegative-integer? x)))
(define (eddsa-curve? v) (memq v '(ed25519 ed448)))
(define (ecx-curve? v) (memq v '(x25519 x448)))

;; bcopy : (U Bytes #f) -> (U ImmutableBytes #f)
;; Avoid shared refs to mutable data.
(define (bcopy x) (if (bytes? x) (bytes->immutable-bytes x) x))

;; ----------------------------------------

(define (-check-bytes fmt v)
  (-check-type fmt 'bytes? bytes? v))
(define (-check-type fmt what pred v)
  (unless (pred v)
    (crypto-error "invalid datum for format\n  expected: ~a\n  format: ~e"
                  what fmt)))

;; ----------------------------------------
;; DSA/DH

(define (check-dsa p q g) ;; checks basic validity, not strength
  (define (bad) (crypto-error "invalid DSA parameters"))
  (unless (= 1 (remainder p q)) (bad))
  (unless (= 1 (mod-expt g q p)) (bad)))

(define (check-dh p g q j) ;; checks basic validity, not strength
  (define (bad) (crypto-error "invalid DH parameters"))
  (cond [j (unless (= p (add1 (* q j))) (bad))]
        [else (unless (= 1 (remainder p q)) (bad))])
  (unless (= (mod-expt g q p) 1) (bad)))

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

;; ----------------------------------------
;; EC Points and Curves

;; References:
;; - SEC1 §2.3 for point to octet encoding
;; - RFC 5480 §2.2: MUST support uncompressed form, MAY support compressed

;; ok-ec-point? : Any -> (U 'comp 'nocomp #f)
(define (ok-ec-point? v)
  (define MIN-COORD-LEN 20) ;; no standard curves smaller than 160-bits
  (define len (and (bytes? v) (bytes-length v)))
  (and len (> len 0)
       (case (bytes-ref v 0)
         [(#x04) (and (> len (* 2 MIN-COORD-LEN)) 'nocomp)]
         [(#x02 #x03) (and (> len MIN-COORD-LEN) 'comp)]
         [else #f])))

;; curve-alias->oid : Symbol/String -> OID/#f
(define (curve-alias->oid alias)
  (curve-name->oid (alias->curve-name alias)))


;; ============================================================
;; Key/Parameters Translation

;; translate-params : Datum ParamsFormat ParamsFormat -> (U Datum #f)
(define (translate-params params-datum from-fmt to-fmt)
  (encode-params to-fmt (parse-params from-fmt params-datum)))

;; translate-key : Datum KeyFormat KeyFormat -> (U Datum #f)
(define (translate-key key-datum from-fmt to-fmt)
  (encode-key to-fmt (parse-key from-fmt key-datum)))

(define (encode-params fmt parsed)
  (match parsed
    [(list 'params 'dsa p q g)
     (encode-params-dsa fmt p q g)]
    [(list 'params 'dh p g q j seed pgen)
     (encode-params-dh fmt p g q j seed pgen)]
    [(list 'params 'ec curve-oid)
     (encode-params-ec fmt curve-oid)]
    [(list 'params 'ec eddsa curve)
     (encode-params-eddsa fmt curve)]
    [(list 'params 'ecx curve)
     (encode-params-ecx fmt curve)]
    [_ #f]))

(define (encode-key fmt parsed)
  (match parsed
    [(list 'public 'rsa n e)
     (encode-pub-rsa fmt n e)]
    [(list 'private 'rsa n e d p q dp dq qInv)
     (encode-priv-rsa fmt n e d p q dp dq qInv)]
    [(list 'public 'dsa p q g y)
     (encode-pub-dsa fmt p q g y)]
    [(list 'private 'dsa p q g y x)
     (encode-priv-dsa fmt p q g y x)]
    [(list 'public 'dh p g q j seed pgen y)
     (encode-pub-dh fmt p g q j seed pgen y)]
    [(list 'private 'dh p g q j seed pgen y x)
     (encode-priv-dh fmt p g q j seed pgen y x)]
    [(list 'public 'ec curve-oid qB)
     (encode-pub-ec fmt curve-oid qB)]
    [(list 'private 'ec curve-oid qB x)
     (encode-priv-ec fmt curve-oid qB x)]
    [(list 'public 'eddsa curve qB)
     (encode-pub-eddsa fmt curve qB)]
    [(list 'private 'eddsa curve qB dB)
     (encode-priv-eddsa fmt curve qB dB)]
    [(list 'public 'ecx curve qB)
     (encode-pub-ecx fmt curve qB)]
    [(list 'private 'ecx curve qB dB)
     (encode-priv-ecx fmt curve qB dB)]
    [_ (encode-params fmt parsed)]))

;; ----------------------------------------

;; References (OpenSSH key format):
;; - https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/ (overview)
;; - RFC 4253 (https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
;; - RFC 8709 (for Ed{25519,448} keys)
(define (parse-openssh-pub s)
  (cond [(regexp-match #rx"^(ssh-rsa|ssh-ed25519|ssh-ed448) ([a-zA-Z0-9+/]+)(?: |$)" s)
         => (lambda (m) (parse-openssh-pub* (cadr m) (base64-decode (caddr m))))]
        [else (err/fmt 'openssh-public)]))
(define (parse-openssh-pub* outer-tag-s bin)
  (define (bad msg) (err/fmt 'openssh-public msg))
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

;; internal formats produces ParseResult, avoids depending on parsing code

;; ---- RSA ----

(define (encode-pub-rsa fmt n e)
  (case fmt
    [(internal internal-public) (ok-public 'rsa n e)]
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
    [(internal internal-private) (ok-private 'rsa n e d p q dp dq qInv)]
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
    [(internal internal-params) (ok-params 'dsa p q g)]
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (dsa-algid p q g))]
    [(DSAParameters Dss-Parms)
     (asn1->bytes/DER Dss-Parms (h-dss-parms p q g))]
    [(rkt-params) (list 'dsa 'params p q g)]
    [else #f]))

(define (encode-pub-dsa fmt p q g y)
  (case fmt
    [(internal internal-public) (ok-public 'dsa p q g y)]
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (dsa-algid p q g) y))]
    [(rkt-public) (list 'dsa 'public p q g y)]
    [else (encode-params-dsa fmt p q g)]))

(define (encode-priv-dsa fmt p q g y x)
  (let ([y (or y (dsa/dh-recompute-y p g x))])
    (case fmt
      [(internal internal-private) (ok-private 'dsa p q g y x)]
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
    [(internal internal-params) (ok-params 'dh p g q j seed pgen)]
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
    [(internal internal-public) (ok-public 'dh p g q j seed pgen y)]
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
      [(internal internal-private) (ok-private 'dh p g q j seed pgen y x)]
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
    [(internal internal-params) (ok-params 'ec curve-oid)]
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (ec-algid curve-oid))]
    [(EcpkParameters)
     (asn1->bytes/DER EcpkParameters (list 'namedCurve curve-oid))]
    [(rkt-params) (list 'ec 'params curve-oid)]
    [else #f]))

(define (encode-pub-ec fmt curve-oid qB)
  (case fmt
    [(internal internal-public) (ok-public 'ec curve-oid qB)]
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER SubjectPublicKeyInfo
                      (h-subject-public-key-info (ec-algid curve-oid) qB))]
    [(rkt-public) (list 'ec 'public curve-oid (bcopy qB))]
    [else (encode-params-ec fmt curve-oid)]))

(define (encode-priv-ec fmt curve-oid qB d)
  (case fmt
    [(internal internal-private) (ok-private 'ec curve-oid qB d)]
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
    [(internal internal-params) (ok-params 'eddsa curve)]
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (eddsa-algid curve))]
    [(rkt-params) (list 'eddsa 'params curve)]
    [else #f]))

(define (encode-pub-eddsa fmt curve qB)
  (case fmt
    [(internal internal-public) (ok-public 'eddsa curve qB)]
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
    [(internal internal-private) (ok-private 'eddsa curve qB dB)]
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
    [(internal internal-params) (ok-params 'ecx curve)]
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY (ecx-algid curve))]
    [(rkt-params) (list 'ecx 'params curve)]
    [else #f]))

(define (encode-pub-ecx fmt curve qB)
  (case fmt
    [(internal internal-public) (ok-public 'ecx curve qB)]
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
    [(internal internal-private) (ok-private 'ecx qB dB)]
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
