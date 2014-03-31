#lang racket/base
(require asn1
         racket/match)
(provide (all-defined-out))

(define (rsa-public-key->SPKI n e)
  (DER-encode
   SubjectPublicKeyInfo
   (list (list rsaEncryption #f)
         `(sequence [modulus ,n] [publicExponent ,e]))))
  
(define (dsa-public-key->SPKI p q g y)
  (DER-encode
   SubjectPublicKeyInfo
   (list (list id-dsa
               `(sequence [p ,p] [q ,q] [g ,g]))
         y)))

(define (dh-public-key->SPKI prime base y)
  (DER-encode
   SubjectPublicKeyInfo
   (list (list dhKeyAgreement
               `(sequence [prime ,prime] [base ,base]))
         y)))

;; ============================================================
;; from RFC 3280 (PKIX, obsoletes RFC 2459)

(define (AlgorithmIdentifier typemap)
  (Wrap (Sequence [algorithm              OBJECT-IDENTIFIER]
                  [#:dependent parameters (get-type algorithm typemap) #:optional])
        #:pre-encode
        (lambda (v) (list->sequence v '(algorithm) '(parameters)))
        #:post-decode
        (lambda (v) (sequence->list v '(algorithm) '(parameters)))))

(define-asn1-type SubjectPublicKeyInfo
  (Wrap (Sequence [algorithm (AlgorithmIdentifier known-public-key-algorithms)]
                  [#:dependent subjectPublicKey (BIT-STRING-containing algorithm)])
        #:pre-encode
        (lambda (v) (list->sequence v '(algorithm subjectPublicKey)))
        #:post-decode
        (lambda (v) (sequence->list v '(algorithm subjectPublicKey)))))

(define (BIT-STRING-containing alg)
  (let ([type (get-type2 (car alg) known-public-key-algorithms)])
    (Wrap BIT-STRING
          #:pre-encode (lambda (v) (bit-string (DER-encode type v) 0))
          #:post-decode (lambda (v) (DER-decode type (bit-string-bytes v))))))

;; ============================================================
;; from RFC 3279 (PKIX, obsoletes RFC 2458)

;; EXPLICIT TAGS

(define rsadsi (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549)))

;; -- One-way Hash Functions

(define md2 (build-OID rsadsi (digestAlgorithm 2) 2))
(define md5 (build-OID rsadsi (digestAlgorithm 2) 5))
(define id-sha1
  (OID (iso 1) (identified-organization 3) (oiw 14) (secsig 3) (algorithms 2) 26))

;; -- DSA Keys and Signatures

;; OID for DSA public key
(define id-dsa
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 1))

;; encoding for DSA public key
(define DSAPublicKey INTEGER) ;; public key, y

(define Dss-Parms
  (Sequence [p   INTEGER]
            [q   INTEGER]
            [g   INTEGER]))

;; OID for DSA signature generated with SHA-1 hash

(define id-dsa-with-sha1
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 3))

;; encoding for DSA signature generated with SHA-1 hash

(define Dss-Sig-Value
  (Sequence [r   INTEGER]
            [s   INTEGER]))

;; --   RSA Keys and Signatures

;; arc for RSA public key and RSA signature OIDs

(define pkcs-1 (build-OID rsadsi (pkcs 1) 1))

;; OID for RSA public keys
(define rsaEncryption (build-OID pkcs-1 1))

;; OID for RSA signature generated with MD2 hash
(define md2WithRSAEncryption (build-OID pkcs-1 2))

;; OID for RSA signature generated with MD5 hash
(define md5WithRSAEncryption (build-OID pkcs-1 4))

;; OID for RSA signature generated with SHA-1 hash
(define sha1WithRSAEncryption (build-OID pkcs-1 5))

;; encoding for RSA public key

(define RSAPublicKey
  (Sequence [modulus         INTEGER] ;; n
            [publicExponent  INTEGER])) ;; e


;; --   Diffie-Hellman Keys

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

;; --   KEA Keys

(define id-keyExchangeAlgorithm (OID 2 16 840 1 101 2 1 1 22))
(define KEA-Parms-Id OCTET-STRING)


;; --   Elliptic Curve Keys, Signatures, and Curves

;; Arc for ECDSA signature OIDS
;; = id-ecSigType

;; OID for ECDSA signatures with SHA-1
;; = ecdsa-with-SHA1

;; OID for an elliptic curve signature
;; format for the value of an ECDSA signature value

(define ECDSA-Sig-Value
  (Sequence [r     INTEGER]
            [s     INTEGER]))

;; recognized field type OIDs are defined in the following arc
;; = id-fieldType

;; where fieldType is prime-field, the parameters are of type Prime-p
;; = prime-field, Prime-p

;; where fieldType is characteristic-two-field, the parameters are
;; of type Characteristic-two
;; = characteristic-two-field, Characteristic-two

;; recognized basis type OIDs are defined in the following arc
;; = id-characteristic-two-basis

;; gnbasis is identified by OID gnBasis and indicates parameters are NULL
;; = gnBasis, NULL

;; trinomial basis is identified by OID tpBasis and indicates
;; parameters of type Trinomial
;; = tpBasis, Trinomial

;; for pentanomial basis is identified by OID ppBasis and indicates
;; parameters of type Pentanomial
;; = ppBasis, Pentanomial

;; The object identifiers gnBasis, tpBasis and ppBasis name three
;; kinds of basis for characteristic-two finite fields

;; FieldElement ::= OCTET STRING             -- Finite field element
;; ECPoint  ::= OCTET STRING                 -- Elliptic curve point

;; Elliptic Curve parameters may be specified explicitly, specified
;; implicitly through a "named curve", or inherited from the CA

;; EcpkParameters = SEC1 ECDomainParameters
;; ECParameters = SEC1 SpecifiedECDomain
;; Curve = SEC1 Curve

(require (prefix-in sec1: asn1/examples/sec1))
(define EcpkParameters (sec1:ECDomainParameters null))
(define ECPoint sec1:ECPoint)

#|
   EcpkParameters ::= CHOICE {
      ecParameters  ECParameters,
      namedCurve    OBJECT IDENTIFIER,
      implicitlyCA  NULL }

   ECParameters  ::= SEQUENCE {         -- Elliptic curve parameters
      version   ECPVer,
      fieldID   FieldID,
      curve     Curve,
      base      ECPoint,                -- Base point G
      order     INTEGER,                -- Order n of the base point
      cofactor  INTEGER  OPTIONAL }     -- The integer h = #E(Fq)/n
   ECPVer ::= INTEGER {ecpVer1(1)}

   Curve  ::= SEQUENCE {
      a     FieldElement,            -- Elliptic curve coefficient a
      b     FieldElement,            -- Elliptic curve coefficient b
      seed  BIT STRING  OPTIONAL }
|#

(define ansi-X9-62 (OID (iso 1) (member-body 2) (us 840) 10045))

(define id-publicKeyType (build-OID ansi-X9-62 (keyType 2)))
(define id-ecPublicKey (build-OID id-publicKeyType 1))

;; -- Named Elliptic Curves in ANSI X9.62.

(define ellipticCurve (build-OID ansi-X9-62 (curves 3)))

(define c-TwoCurve (build-OID ellipticCurve (characteristicTwo 0)))
(define c2pnb163v1 (build-OID c-TwoCurve  1))
(define c2pnb163v2 (build-OID c-TwoCurve  2))
(define c2pnb163v3 (build-OID c-TwoCurve  3))
(define c2pnb176w1 (build-OID c-TwoCurve  4))
(define c2tnb191v1 (build-OID c-TwoCurve  5))
(define c2tnb191v2 (build-OID c-TwoCurve  6))
(define c2tnb191v3 (build-OID c-TwoCurve  7))
(define c2onb191v4 (build-OID c-TwoCurve  8))
(define c2onb191v5 (build-OID c-TwoCurve  9))
(define c2pnb208w1 (build-OID c-TwoCurve 10))
(define c2tnb239v1 (build-OID c-TwoCurve 11))
(define c2tnb239v2 (build-OID c-TwoCurve 12))
(define c2tnb239v3 (build-OID c-TwoCurve 13))
(define c2onb239v4 (build-OID c-TwoCurve 14))
(define c2onb239v5 (build-OID c-TwoCurve 15))
(define c2pnb272w1 (build-OID c-TwoCurve 16))
(define c2pnb304w1 (build-OID c-TwoCurve 17))
(define c2tnb359v1 (build-OID c-TwoCurve 18))
(define c2pnb368w1 (build-OID c-TwoCurve 19))
(define c2tnb431r1 (build-OID c-TwoCurve 20))

(define primeCurve (build-OID ellipticCurve (prime 1)))
(define prime192v1 (build-OID primeCurve  1))
(define prime192v2 (build-OID primeCurve  2))
(define prime192v3 (build-OID primeCurve  3))
(define prime239v1 (build-OID primeCurve  4))
(define prime239v2 (build-OID primeCurve  5))
(define prime239v3 (build-OID primeCurve  6))
(define prime256v1 (build-OID primeCurve  7))


;; ============================================================
;; RSA, PKCS #1

;; Representation of RSA private key with information for the CRT
;; algorithm.
(define-asn1-type RSAPrivateKey
  (Sequence [version           Version]
            [modulus           INTEGER] ;; n
            [publicExponent    INTEGER] ;; e
            [privateExponent   INTEGER] ;; d
            [prime1            INTEGER] ;; p
            [prime2            INTEGER] ;; q
            [exponent1         INTEGER] ;; d mod (p-1)
            [exponent2         INTEGER] ;; d mod (q-1)
            [coefficient       INTEGER] ;; (inverse of q) mod p
            [otherPrimeInfos   OtherPrimeInfos #:optional]))

(define Version INTEGER)
(define Version:two-prime 0)
(define Version:multi 1) ;; version must be multi if otherPrimeInfos present

(define-asn1-type OtherPrimeInfos
  (SequenceOf OtherPrimeInfo)) ;; SIZE(1..MAX)

(define OtherPrimeInfo
  (Sequence [prime             INTEGER] ;; ri
            [exponent          INTEGER] ;; di
            [coefficient       INTEGER])) ;; ti

;; ============================================================

(define dhKeyAgreement (build-OID rsadsi (pkcs 1) 3 1))

(define DHParameter
  (Sequence [prime INTEGER]
            [base INTEGER]
            [privateValueLength INTEGER #:optional]))

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
        (list id-ecPublicKey  EcpkParameters   ECPoint)))
