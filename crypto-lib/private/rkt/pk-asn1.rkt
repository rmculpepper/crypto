;; Copyright 2014-2018 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require asn1)
(provide (all-defined-out))

#|
============================================================
PK key and parameter formats

References:
 - PKIX RFCs
   - http://www.ietf.org/rfc/rfc5758.txt
   - http://www.ietf.org/rfc/rfc3280.txt
   - http://www.ietf.org/rfc/rfc2459.txt
 - PKIX Algorithms and Identifiers RFCs
   - http://www.ietf.org/rfc/rfc5480.txt
   - http://www.ietf.org/rfc/rfc3279.txt
 - http://tools.ietf.org/html/rfc5912
   - updated ASN.1 modules for PKIX
 - PKCS#3: ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-3.asc
   - ASN.1 for DHParameter, dhKeyAgreement OID for AlgorithmIdentifier
 - PKCS#8: http://www.ietf.org/rfc/rfc5208.txt
   - ASN.1 for PrivateKeyInfo and EncryptedPrivateKeyInfo
   - note: allows BER encoding, not just DER
   - https://tools.ietf.org/html/rfc5958
     - obsoletes PKCS#8 ??
   - RFC 5915: http://tools.ietf.org/html/rfc5915
     - EC private key structure (for use with PKCS #8)
 - http://csrc.nist.gov/groups/ST/crypto_apps_infra/csor/algorithms.html#modules
   - some OIDs for AES, digests, etc
 - http://www.cryptsoft.com/pkcs11doc/v220/group__SEC__12__6__WRAPPING__UNWRAPPING__PRIVATE__KEYS.html
 - https://tools.ietf.org/html/draft-ietf-curdle-pkix-07 (EdDSA; X25519, etc)
|#

;; ============================================================

;; Helper for embedding DER into larger structures
(define ANY/DER (WRAP ANY
                      #:encode (lambda (v) (bytes->asn1/DER ANY v))
                      #:decode (lambda (v) (asn1->bytes/DER ANY v))))

;; BIT-STRING-containing : (U ASN1-Type #f) -> ASN1-Type
(define (BIT-STRING-containing type)
  (cond [type
         (WRAP BIT-STRING
               #:encode (lambda (v) (bit-string (asn1->bytes/DER type v) 0))
               #:decode (lambda (v) (bytes->asn1/DER type (bit-string-bytes v))))]
        [else
         (WRAP BIT-STRING
               #:encode (lambda (v) (bit-string v 0))
               #:decode (lambda (v) (bit-string-bytes v)))]))

;; ============================================================

(define-asn1-type AlgorithmIdentifier
  (let ([typemap known-public-key-algorithms])
    (SEQUENCE [algorithm              OBJECT-IDENTIFIER]
              [parameters #:dependent (get-type 1 algorithm typemap) #:optional])))

(define AlgorithmIdentifier/DER
  (SEQUENCE [algorithm  OBJECT-IDENTIFIER]
            [parameters ANY/DER #:optional]))

(define-asn1-type SubjectPublicKeyInfo
  (SEQUENCE [algorithm AlgorithmIdentifier]
            [subjectPublicKey #:dependent (SPKI-PublicKey algorithm)]))

(define (SPKI-PublicKey algorithm)
  (BIT-STRING-containing
   (get-type 2 (hash-ref algorithm 'algorithm) known-public-key-algorithms)))

;; ============================================================
;; RSA

(define rsadsi (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549)))
(define pkcs-1 (build-OID rsadsi (pkcs 1) 1))

;; OID for RSA public keys
(define rsaEncryption (build-OID pkcs-1 1))

;; encoding for RSA public key
(define RSAPublicKey
  (SEQUENCE [modulus         INTEGER] ;; n
            [publicExponent  INTEGER])) ;; e

;; ----

(define-asn1-type RSAPrivateKey
  (SEQUENCE [version           INTEGER]
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
  (SEQUENCE-OF OtherPrimeInfo)) ;; SIZE(1..MAX)

(define OtherPrimeInfo
  (SEQUENCE [prime             INTEGER] ;; ri
            [exponent          INTEGER] ;; di
            [coefficient       INTEGER])) ;; ti

;; ============================================================
;; DSA

;; OID for DSA public key
(define id-dsa
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 1))

;; encoding for DSA public key
(define DSAPublicKey INTEGER) ;; public key, y

(define Dss-Parms
  (SEQUENCE [p   INTEGER]
            [q   INTEGER]
            [g   INTEGER]))

(define Dss-Sig-Value
  (SEQUENCE [r   INTEGER]
            [s   INTEGER]))

;; used by OpenSSL
(define DSAPrivateKey
  (SEQUENCE [version INTEGER] ;; = 0
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
  (SEQUENCE [seed          BIT-STRING]
            [pgenCounter   INTEGER]))

(define DomainParameters
  (SEQUENCE [p       INTEGER] ;; odd prime, p=jq +1
            [g       INTEGER] ;; generator, g
            [q       INTEGER] ;; factor of p-1
            [j       INTEGER #:optional] ;; subgroup factor, j>= 2
            [validationParms  ValidationParms #:optional]))

;; ----

(define dhKeyAgreement (build-OID rsadsi (pkcs 1) 3 1))

(define DHParameter
  (SEQUENCE [prime INTEGER]
            [base INTEGER]
            [privateValueLength INTEGER #:optional]))

;; ============================================================
;; EC

;; EcpkParameters = SEC1 ECDomainParameters
;; ECParameters = SEC1 SpecifiedECDomain
;; Curve = SEC1 Curve

(define ECDSA-Sig-Value
  (SEQUENCE [r     INTEGER]
            [s     INTEGER]))

(define EcpkParameters
  (CHOICE [namedCurve    OBJECT-IDENTIFIER]
          #|
          [ecParameters  ECParameters]
          [implicitlyCA  NULL]
          |#))

(define ECPoint OCTET-STRING)

(define certicom (OID (iso 1) (identifier-organization 3) (certicom 132)))
(define ansi-X9-62 (OID (iso 1) (member-body 2) (us 840) (ansi-X9-62 10045)))

;;(define id-publicKeyType (build-OID ansi-X9-62 (keyType 2)))
(define id-ecPublicKey (build-OID ansi-X9-62 (keyType 2) (ecPublicKey 1)))

(define id-brainpool
  (OID (iso 1) (identified-organization 3) (teletrust 36) (algorithm 3) (signature-algorithm 3)
       (ecSign 2) 8 1 (versionOne 1)))
(define c-TwoCurve (build-OID ansi-X9-62 (curves 3) (characteristicTwo 0)))
(define primeCurve (build-OID ansi-X9-62 (curves 3) (prime 1)))

(define known-curves
  (list
   ;; Note: Names correspond with canonical names (cf catalog, curve-aliases).
   ;; References: Curves from RFC 5480 (http://www.ietf.org/rfc/rfc5480.txt)
   ;; and SEC2 (http://www.secg.org/sec2-v2.pdf).
   ;; -- Prime-order fields --
   (cons 'secp192k1 (build-OID certicom (curve 0) 31))
   (cons 'secp192r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 1))
   (cons 'secp224k1 (build-OID certicom (curve 0) 32))
   (cons 'secp224r1 (build-OID certicom (curve 0) 33))
   (cons 'secp256k1 (build-OID certicom (curve 0) 10))
   (cons 'secp256r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 7))
   (cons 'secp384r1 (build-OID certicom (curve 0) 34))
   (cons 'secp521r1 (build-OID certicom (curve 0) 35))
   ;; -- Characteristic 2 fields --
   (cons 'sect163k1 (build-OID certicom (curve 0) 1))
   (cons 'sect163r1 (build-OID certicom (curve 0) 2))
   (cons 'sect163r2 (build-OID certicom (curve 0) 15))
   (cons 'sect233k1 (build-OID certicom (curve 0) 26))
   (cons 'sect233r1 (build-OID certicom (curve 0) 27))
   (cons 'sect239k1 (build-OID certicom (curve 0) 3))
   (cons 'sect283k1 (build-OID certicom (curve 0) 16))
   (cons 'sect283r1 (build-OID certicom (curve 0) 17))
   (cons 'sect409k1 (build-OID certicom (curve 0) 36))
   (cons 'sect409r1 (build-OID certicom (curve 0) 37))
   (cons 'sect571k1 (build-OID certicom (curve 0) 38))
   (cons 'sect571r1 (build-OID certicom (curve 0) 39))

   ;; Brainpool named curves
   ;; References: https://tools.ietf.org/html/rfc5639
   (cons 'brainpoolP160r1 (build-OID id-brainpool 1))
   (cons 'brainpoolP160t1 (build-OID id-brainpool 2))
   (cons 'brainpoolP192r1 (build-OID id-brainpool 3))
   (cons 'brainpoolP192t1 (build-OID id-brainpool 4))
   (cons 'brainpoolP224r1 (build-OID id-brainpool 5))
   (cons 'brainpoolP224t1 (build-OID id-brainpool 6))
   (cons 'brainpoolP256r1 (build-OID id-brainpool 7))
   (cons 'brainpoolP256t1 (build-OID id-brainpool 8))
   (cons 'brainpoolP320r1 (build-OID id-brainpool 9))
   (cons 'brainpoolP320t1 (build-OID id-brainpool 10))
   (cons 'brainpoolP384r1 (build-OID id-brainpool 11))
   (cons 'brainpoolP384t1 (build-OID id-brainpool 12))
   (cons 'brainpoolP512r1 (build-OID id-brainpool 13))
   (cons 'brainpoolP512t1 (build-OID id-brainpool 14))

   ;; Named Elliptic Curves in ANSI X9.62.
   (cons 'c2pnb163v1 (build-OID c-TwoCurve  1))
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

(define-asn1-type ECPrivateKey
  (SEQUENCE [version        INTEGER] ;; ecPrivkeyVer1
            [privateKey     OCTET-STRING]
            [parameters #:explicit 0 EcpkParameters #:optional]
            [publicKey  #:explicit 1 (BIT-STRING-containing #f) #:default #f]))

(define ecPrivkeyVer1 1)

;; ============================================================
;; EdDSA

(define id-edwards-curve-algs (OID 1 3 101))
(define id-X25519    (build-OID id-edwards-curve-algs 110))
(define id-X448      (build-OID id-edwards-curve-algs 111))
(define id-Ed25519   (build-OID id-edwards-curve-algs 112))
(define id-Ed448     (build-OID id-edwards-curve-algs 113))

;; ============================================================

(define-asn1-type PrivateKeyInfo
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]))

(define-asn1-type OneAsymmetricKey
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]
            [publicKey #:implicit 1 #:dependent (OAK-PublicKey privateKeyAlgorithm)
                       #:default #f]))

(define (PrivateKey alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (cond [(get-type 1 alg-oid known-private-key-formats)
         => (lambda (type)
              (WRAP OCTET-STRING
                    #:encode (lambda (v) (asn1->bytes/DER type v))
                    #:decode (lambda (v) (bytes->asn1/DER type v))))]
        [else OCTET-STRING]))

(define (OAK-PublicKey algorithm)
  (BIT-STRING-containing
   (get-type 2 (hash-ref algorithm 'algorithm) known-private-key-formats)))

(define Attributes (SET-OF ANY/DER))

;; ============================================================
;; Some utilities

;; get-type : Nat Key (Listof (list Key X ...)) -> X
(define (get-type index key typemap)
  (cond [(assoc key typemap)
         => (lambda (e) (list-ref e index))]
        [else (error 'get-type "key not found\n  key: ~e" key)]))

;; ============================================================

;; for SubjectPublicKeyInfo
(define known-public-key-algorithms
  ;;          alg-oid         params-type      pub-key-type (SPKI)
  (list (list rsaEncryption   NULL             RSAPublicKey)
        (list id-dsa          Dss-Parms        DSAPublicKey)
        ;; DH: PKIX says use dhpublicnumber; OpenSSL uses PKCS#3 OID
        (list dhpublicnumber  DomainParameters DHPublicKey)
        (list dhKeyAgreement  DHParameter      DHPublicKey)
        ;; Special case!: the bitstring's octets are ECPoint, not a
        ;; BER-encoding of ECPoint
        (list id-ecPublicKey  EcpkParameters   #f)
        (list id-Ed25519      NULL             #f)
        (list id-Ed448        NULL             #f)
        (list id-X25519       NULL             #f)
        (list id-X448         NULL             #f)))

;; for PKCS #8 PrivateKeyInfo and OneAsymmetricKey
(define known-private-key-formats
  ;;          alg-oid         priv-key-type    pub-key-type (OAK)
  (list (list rsaEncryption   RSAPrivateKey    #f)
        (list id-dsa          INTEGER          INTEGER)
        (list dhKeyAgreement  INTEGER          INTEGER)
        (list id-ecPublicKey  ECPrivateKey     #f)
        (list id-Ed25519      OCTET-STRING     #f)
        (list id-Ed448        OCTET-STRING     #f)
        (list id-X25519       OCTET-STRING     #f)
        (list id-X448         OCTET-STRING     #f)))
