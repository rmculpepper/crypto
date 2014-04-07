#lang racket/base
(require asn1
         asn1/sequence)
(provide (all-defined-out))

;; References:
;; - RFC 3280, RFC 3279
;; - SEC 1
;; - PKCS #8: http://www.ietf.org/rfc/rfc5208.txt
;; - http://tools.ietf.org/html/rfc5915
;; - http://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__6__WRAPPING__UNWRAPPING__PRIVATE__KEYS.html

;; ============================================================

(define-asn1-type AlgorithmIdentifier
  (let ([typemap known-public-key-algorithms])
    (Sequence [algorithm              OBJECT-IDENTIFIER]
              [#:dependent parameters (get-type algorithm typemap) #:optional])))

(define-asn1-type SubjectPublicKeyInfo
  (Sequence [algorithm AlgorithmIdentifier]
            [#:dependent subjectPublicKey (BIT-STRING-containing algorithm)]))

(define (BIT-STRING-containing alg)
  (define alg-oid (sequence-ref alg 'algorithm))
  (cond [(get-type2 alg-oid known-public-key-algorithms)
         => (lambda (type)
              (Wrap BIT-STRING
                    #:pre-encode (lambda (v) (bit-string (DER-encode type v) 0))
                    #:post-decode (lambda (v) (DER-decode type (bit-string-bytes v)))))]
        [else
         (Wrap BIT-STRING
               #:pre-encode (lambda (v) (bit-string v 0))
               #:post-decode (lambda (v) (bit-string-bytes v)))]))

;; ============================================================
;; RSA

(define rsadsi (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549)))
(define pkcs-1 (build-OID rsadsi (pkcs 1) 1))

;; OID for RSA public keys
(define rsaEncryption (build-OID pkcs-1 1))

;; encoding for RSA public key
(define RSAPublicKey
  (Sequence [modulus         INTEGER] ;; n
            [publicExponent  INTEGER])) ;; e

;; ----

(define-asn1-type RSAPrivateKey
  (Sequence [version           INTEGER]
            [modulus           INTEGER] ;; n
            [publicExponent    INTEGER] ;; e
            [privateExponent   INTEGER] ;; d
            [prime1            INTEGER] ;; p
            [prime2            INTEGER] ;; q
            [exponent1         INTEGER] ;; d mod (p-1)
            [exponent2         INTEGER] ;; d mod (q-1)
            [coefficient       INTEGER] ;; (inverse of q) mod p
            [otherPrimeInfos   OtherPrimeInfos #:optional]))

(define RSA:Version:two-prime 0)
(define RSA:Version:multi 1) ;; version must be multi if otherPrimeInfos present

(define-asn1-type OtherPrimeInfos
  (SequenceOf OtherPrimeInfo)) ;; SIZE(1..MAX)

(define OtherPrimeInfo
  (Sequence [prime             INTEGER] ;; ri
            [exponent          INTEGER] ;; di
            [coefficient       INTEGER])) ;; ti

;; ----

(define (rsa-private-key->public-key s)
  `(sequence [modulus ,(sequence-ref s 'modulus)]
             [publicExponent ,(sequence-ref s 'publicExponent)]))

;; ============================================================
;; DSA

;; OID for DSA public key
(define id-dsa
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 1))

;; encoding for DSA public key
(define DSAPublicKey INTEGER) ;; public key, y

(define Dss-Parms
  (Sequence [p   INTEGER]
            [q   INTEGER]
            [g   INTEGER]))

(define Dss-Sig-Value
  (Sequence [r   INTEGER]
            [s   INTEGER]))

;; used by OpenSSL
(define DSAPrivateKey
  (Sequence [version INTEGER] ;; = 0
            [p INTEGER]
            [q INTEGER]
            [g INTEGER]
            [y INTEGER]
            [x INTEGER]))

;; ============================================================
;; DH

(define dhpublicnumber
  (OID (iso 1) (member-body 2) (us 840) (ansi-x942 10046) (number-type 2) 1))

;; encoding for DSA public key
(define DHPublicKey INTEGER) ;; public key, y = g^x mod p

(define ValidationParms
  (Sequence [seed          BIT-STRING]
            [pgenCounter   INTEGER]))

(define DomainParameters
  (Sequence [p       INTEGER] ;; odd prime, p=jq +1
            [g       INTEGER] ;; generator, g
            [q       INTEGER] ;; factor of p-1
            [j       INTEGER #:optional] ;; subgroup factor, j>= 2
            [validationParms  ValidationParms #:optional]))

;; ----

(define dhKeyAgreement (build-OID rsadsi (pkcs 1) 3 1))

(define DHParameter
  (Sequence [prime INTEGER]
            [base INTEGER]
            [privateValueLength INTEGER #:optional]))

;; ============================================================
;; EC

;; EcpkParameters = SEC1 ECDomainParameters
;; ECParameters = SEC1 SpecifiedECDomain
;; Curve = SEC1 Curve

(define ECDSA-Sig-Value
  (Sequence [r     INTEGER]
            [s     INTEGER]))

(define EcpkParameters
  (Choice [namedCurve    OBJECT-IDENTIFIER]
          #|
          [ecParameters  ECParameters]
          [implicitlyCA  NULL]
          |#))

(define ECPoint OCTET-STRING)

(define ansi-X9-62 (OID (iso 1) (member-body 2) (us 840) 10045))
(define id-publicKeyType (build-OID ansi-X9-62 (keyType 2)))
(define id-ecPublicKey (build-OID id-publicKeyType 1))

;; -- Named Elliptic Curves in ANSI X9.62.

(define ellipticCurve (build-OID ansi-X9-62 (curves 3)))
(define c-TwoCurve (build-OID ellipticCurve (characteristicTwo 0)))
(define primeCurve (build-OID ellipticCurve (prime 1)))

(define known-named-curves
  (list (cons 'c2pnb163v1 (build-OID c-TwoCurve  1))
        (cons 'c2pnb163v2 (build-OID c-TwoCurve  2))
        (cons 'c2pnb163v3 (build-OID c-TwoCurve  3))
        (cons 'c2pnb176w1 (build-OID c-TwoCurve  4))
        (cons 'c2tnb191v1 (build-OID c-TwoCurve  5))
        (cons 'c2tnb191v2 (build-OID c-TwoCurve  6))
        (cons 'c2tnb191v3 (build-OID c-TwoCurve  7))
        (cons 'c2onb191v4 (build-OID c-TwoCurve  8))
        (cons 'c2onb191v5 (build-OID c-TwoCurve  9))
        (cons 'c2pnb208w1 (build-OID c-TwoCurve 10))
        (cons 'c2tnb239v1 (build-OID c-TwoCurve 11))
        (cons 'c2tnb239v2 (build-OID c-TwoCurve 12))
        (cons 'c2tnb239v3 (build-OID c-TwoCurve 13))
        (cons 'c2onb239v4 (build-OID c-TwoCurve 14))
        (cons 'c2onb239v5 (build-OID c-TwoCurve 15))
        (cons 'c2pnb272w1 (build-OID c-TwoCurve 16))
        (cons 'c2pnb304w1 (build-OID c-TwoCurve 17))
        (cons 'c2tnb359v1 (build-OID c-TwoCurve 18))
        (cons 'c2pnb368w1 (build-OID c-TwoCurve 19))
        (cons 'c2tnb431r1 (build-OID c-TwoCurve 20))
        (cons 'prime192v1 (build-OID primeCurve  1))
        (cons 'prime192v2 (build-OID primeCurve  2))
        (cons 'prime192v3 (build-OID primeCurve  3))
        (cons 'prime239v1 (build-OID primeCurve  4))
        (cons 'prime239v2 (build-OID primeCurve  5))
        (cons 'prime239v3 (build-OID primeCurve  6))
        (cons 'prime256v1 (build-OID primeCurve  7))))

;; ----

(define ECPrivateKey
  (Sequence [version        INTEGER] ;; ecPrivkeyVer1
            [privateKey     OCTET-STRING]
            [parameters #:explicit 0 EcpkParameters #:optional]
            [publicKey  #:explicit 1 BIT-STRING #:optional]))

(define ecPrivkeyVer1 1)

;; ============================================================

(define-asn1-type PrivateKeyInfo
  (Sequence [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier]
            [#:dependent privateKey    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]))

(define (PrivateKey alg)
  (define alg-oid (sequence-ref alg 'algorithm))
  (cond [(get-type alg-oid known-private-key-formats)
         => (lambda (type)
              (Wrap OCTET-STRING
                    #:pre-encode
                    (lambda (v) (DER-encode type v))
                    #:post-decode
                    (lambda (v) (DER-decode type v))))]
        [else OCTET-STRING]))

(define Attributes (SetOf (Wrap ANY #:decode values #:encode values)))

;; ============================================================
;; Some utilities

;; get-type : Key (listof (list Key Type)) -> Type
(define (get-type key typemap)
  (cond [(assoc key typemap)
         => (lambda (e) (cadr e))]
        [else (error 'get-type "key not found\n  key: ~e" key)]))

;; get-type2 : Key (listof (list Key Type)) -> Type
(define (get-type2 key typemap)
  (cond [(assoc key typemap)
         => (lambda (e) (caddr e))]
        [else (error 'get-type2 "key not found\n  key: ~e" key)]))

;; ============================================================

;; for SubjectPublicKeyInfo
(define known-public-key-algorithms
  (list (list rsaEncryption   NULL             RSAPublicKey)
        (list id-dsa          Dss-Parms        DSAPublicKey)
        ;; DH: PKIX says use dhpublicnumber; OpenSSL uses PKCS#3 OID
        (list dhpublicnumber  DomainParameters DHPublicKey)
        (list dhKeyAgreement  DHParameter      DHPublicKey)
        ;; ECPoint octets are bit-string contents
        (list id-ecPublicKey  EcpkParameters   #f)))

;; for PKCS #8 PrivateKeyInfo
(define known-private-key-formats
  (list (list rsaEncryption   RSAPrivateKey)
        (list id-dsa          INTEGER)
        (list dhKeyAgreement  INTEGER)
        (list id-ecPublicKey  ECPrivateKey)))
