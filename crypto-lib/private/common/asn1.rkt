;; Copyright 2014-2019 Ryan Culpepper
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
(require asn1
         "error.rkt")
(provide (all-defined-out))

;; References
;; - RFC 5911 (CMS), 5912 (PKIX), 6268 (more CMS+PKIX)
;;   - updated asn1 modules for previous RFCs:
;;     - 3370, 3565, 3851, 3852, 4108, 4998, 5035, 5083, 5084, 5275
;;     - 2560, 2986, 3279, 3852, 4055, 4210, 4211, 5055, 5272, 5280, 5755
;;     - 3274, 3779, 6019, 4073, 4231, 4334, 5083, 5652, 5752
;; - RFC 5915: EC private key structure
;; - RFC 5958: PKCS #8 private key info
;; - RFC 7914: scrypt
;; - RFC 8018: PKCS #5 password-based cryptography
;; - RFC 8103: Chacha20-Poly1305
;; - RFC 8410: {Ed,X}{25519,448}
;; - NIST: AES, SHA2, SHA3
;;   - https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
;; - PKCS #3: DH
;;   - ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-3.asc


;; ================================================================================
;; UTILITIES
;; ================================================================================


;; ============================================================
;; Relations

(struct rel (heading tuples) #:transparent)
(define (relation* heading tuples)
  (define nfields (vector-length heading))
  (for ([tuple (in-vector tuples)])
    (unless (= (vector-length tuple) nfields)
      (error 'relation "wrong number of fields\n  expected: ~s fields\n  tuple: ~e"
             nfields tuple)))
  (rel heading tuples))

(define (relation-field-index rel keyfield #:who [who 'relation-field-index])
  (or (for/first ([field (in-vector (rel-heading rel))]
                  [index (in-naturals)]
                  #:when (equal? field keyfield))
        index)
      (error who "field not found in relation\n  field: ~e\n  heading: ~e"
             keyfield (rel-heading rel))))

(define (relation-find rel keyfield key #:who [who 'relation-find])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/first ([tuple (in-vector (rel-tuples rel))]
              #:when (equal? (vector-ref tuple keyindex) key))
    tuple))

(define (relation-ref rel keyfield key wantfield #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (vector-ref tuple (relation-field-index rel wantfield #:who who)))]
        [else #f]))

(define (relation-ref* rel keyfield key wantfields #:who [who 'relation-ref])
  (cond [(relation-find rel keyfield key #:who who)
         => (lambda (tuple)
              (map (lambda (wantfield)
                     (vector-ref tuple (relation-field-index rel wantfield #:who who)))
                   wantfields))]
        [else #f]))

(define (relation-column rel keyfield #:who [who 'relation-column])
  (define keyindex (relation-field-index rel keyfield #:who who))
  (for/vector ([tuple (in-vector (rel-tuples rel))])
    (vector-ref tuple keyindex)))

(define-syntax-rule (relation #:heading [field ...] #:tuples [value ...] ...)
  (relation* (vector field ...) (vector (vector value ...) ...)))

;; ============================================================
;; ASN1 Helpers

;; Helper for embedding DER into larger structures
(define ANY/DER
  (WRAP ANY
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

;; OCTET-STRING-containing : (U ASN1-Type #f) -> ASN1-Type
(define (OCTET-STRING-containing type)
  (cond [type
         (WRAP OCTET-STRING
               #:encode (lambda (v) (asn1->bytes/DER type v))
               #:decode (lambda (v) (bytes->asn1/DER type v)))]
        [else OCTET-STRING]))

;; useful for giving SEQUENCE w/ optional fields a fixed shape for match
(define (ensure-keys h keys)
  (for/fold ([h h]) ([key (in-list keys)])
    (if (hash-has-key? h key) h (hash-set h key #f))))


;; ================================================================================
;; ASN1 for Cryptography
;; ================================================================================


;; ============================================================
;; Object Identifiers

;; Common prefixes

(define rsadsi (OID (iso 1) (member-body 2) (us 840) (rsadsi 113549)))
(define pkcs-1 (build-OID rsadsi (pkcs 1) 1))
(define pkcs-3 (build-OID rsadsi (pkcs 1) 3))
(define pkcs-5 (build-OID rsadsi (pkcs 1) 5))
(define pkcs-9 (build-OID rsadsi (pkcs 1) 9))

(define certicom (OID (iso 1) (identified-organization 3) (certicom 132)))
(define ansi-X9-62 (OID (iso 1) (member-body 2) (us 840) (ansi-X9-62 10045)))

(define nistAlgorithms
  (OID (joint-iso-itu-t 2) (country 16) (us 840) (organization 1)
       (gov 101) (csor 3) (nistAlgorithms 4)))

;; from PKIX-Algs-2009 (1.3.6.1.5.5.7.0.56)

(define rsaEncryption (build-OID pkcs-1 1))
(define id-dsa
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 1))
(define dhpublicnumber
  (OID (iso 1) (member-body 2) (us 840) (ansi-x942 10046) (number-type 2) 1))
(define id-ecPublicKey (build-OID ansi-X9-62 (keyType 2) 1))
(define id-ecDH (build-OID certicom (schemes 1) (ecdh 12)))
(define id-ecMQV (build-OID certicom (schemes 1) (ecmqv 13)))

;; (define id-keyExchangeAlgorithm
;;   (OID (joint-iso-itu-t 2) (country 16) (us 840) (organization 1)
;;        (gov 101) (dod 2) (infosec 1) (algorithms 1) 22))

;; (define secp192r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 1))
;; (define sect163k1 (build-OID certicom (curve 0) 1))
;; (define sect163r2 (build-OID certicom (curve 0) 15))
;; (define secp224r1 (build-OID certicom (curve 0) 33))
;; (define sect233k1 (build-OID certicom (curve 0) 26))
;; (define sect233r1 (build-OID certicom (curve 0) 27))
;; (define secp256r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 7))
;; (define sect283k1 (build-OID certicom (curve 0) 16))
;; (define sect283r1 (build-OID certicom (curve 0) 17))
;; (define secp384r1 (build-OID certicom (curve 0) 34))
;; (define sect409k1 (build-OID certicom (curve 0) 36))
;; (define sect409r1 (build-OID certicom (curve 0) 37))
;; (define secp521r1 (build-OID certicom (curve 0) 35))
;; (define sect571k1 (build-OID certicom (curve 0) 38))
;; (define sect571r1 (build-OID certicom (curve 0) 39))

(define id-md2 (build-OID rsadsi (digestAlgorithm 2) 2))
(define id-md5 (build-OID rsadsi (digestAlgorithm 2) 5))
(define id-sha1
  (OID (iso 1) (identified-organization 3) (oiw 14) (secsig 3) (algorithm 2) 26))

(define md2WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 2))
(define md5WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 4))
(define sha1WithRSAEncryption (build-OID rsadsi (pkcs 1) (pkcs-1 1) 5))

(define dsa-with-sha1
  (OID (iso 1) (member-body 2) (us 840) (x9-57 10040) (x9algorithm 4) 3))
(define dsa-with-sha224 (build-OID nistAlgorithms (id-dsa-with-sha2 3) 1))
(define dsa-with-sha256 (build-OID nistAlgorithms (id-dsa-with-sha2 3) 2))

(define ecdsa-with-SHA1 (build-OID ansi-X9-62 (signatures 4) 1))
(define ecdsa-with-SHA224 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 1))
(define ecdsa-with-SHA256 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 2))
(define ecdsa-with-SHA384 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 3))
(define ecdsa-with-SHA512 (build-OID ansi-X9-62 (signatures 4) (ecdsa-with-SHA2 3) 4))

;; from PKIX-PSS-OAEP-Algorithms-2009 (1.3.6.1.5.5.7.0.54)

;; (define id-sha224 (build-OID nistAlgorithms (hashalgs 2) 4))
;; (define id-sha256 (build-OID nistAlgorithms (hashalgs 2) 1))
;; (define id-sha384 (build-OID nistAlgorithms (hashalgs 2) 2))
;; (define id-sha512 (build-OID nistAlgorithms (hashalgs 2) 3))

;; (define rsaEncryption (build-OID pkcs-1 1))
(define id-RSAES-OAEP (build-OID pkcs-1 7))
(define id-mgf1 (build-OID pkcs-1 8))
(define id-pSpecified (build-OID pkcs-1 9))
(define id-RSASSA-PSS (build-OID pkcs-1 10))

(define sha224WithRSAEncryption (build-OID pkcs-1 14))
(define sha256WithRSAEncryption (build-OID pkcs-1 11))
(define sha384WithRSAEncryption (build-OID pkcs-1 12))
(define sha512WithRSAEncryption (build-OID pkcs-1 13))

;; from CryptographicMessageSyntaxAlgorithms-2009 (1.2.840.113549.1.9.160.37)

;; (define rsaEncryption (build-OID pkcs-1 1))
;; (define id-alg-ESDH (build-OID pkcs-9 (smime 16) (alg 3) 5))
;; (define id-alg-SSDH (build-OID pkcs-9 (smime 16) (alg 3) 10))
;; (define id-alg-CMS3DESwrap (build-OID pkcs-9 (smime 16) (alg 3) 6))
;; (define id-alg-CMSRC2wrap (build-OID pkcs-9 (smime 16) (alg 3) 7))
(define des-ede3-cbc (build-OID rsadsi (encryptionAlgorithm 3) 7))
;; (define rc2-cbc (build-OID rsadsi (encryptionAlgorithm 3) 2))
;; (define id-PBKDF2 (build-OID rsadsi (pkcs 1) (pkcs-5 5) 12))

(define hMAC-SHA1
  (OID (iso 1) (identified-organization 3) (dod 6) (internet 1) (security 5)
       (mechanisms 5) 8 1 2))

;; from CMSAesRsaesOaep-2009 (1.2.840.113549.1.9.16.0.38)

;; (define aes (build-OID nistAlgorithms 1))
;; (define id-aes128-CBC (build-OID aes 2))
;; (define id-aes192-CBC (build-OID aes 22))
;; (define id-aes256-CBC (build-OID aes 42))
;; (define id-aes128-wrap (build-OID aes 5))
;; (define id-aes192-wrap (build-OID aes 25))
;; (define id-aes256-wrap (build-OID aes 45))

;; CMS-AES-CCM-and-AES-GCM-2009 (1.2.840.113549.1.9.16.0.44)

;; (define aes (build-OID nistAlgorithms 1))
;; (define id-aes128-CCM (build-OID aes 7))
;; (define id-aes192-CCM (build-OID aes 27))
;; (define id-aes256-CCM (build-OID aes 47))
;; (define id-aes128-GCM (build-OID aes 6))
;; (define id-aes192-GCM (build-OID aes 26))
;; (define id-aes256-GCM (build-OID aes 46))

;; from PKIX1Explicit-2009 (1.3.6.1.5.5.7.0.51)

(define id-pkix
  (OID (iso 1) (identified-organization 3) (dod 6) (internet 1) (security 5)
       (mechanisms 5) (pkix 7)))

;; from HMAC-2010 (1.3.6.1.5.5.7.0.74)

;; (define digestAlgorithm (build-OID rsadsi 2))
;; (define id-hmacWithSHA224 (build-OID digestAlgorithm 8))
;; (define id-hmacWithSHA256 (build-OID digestAlgorithm 9))
;; (define id-hmacWithSHA384 (build-OID digestAlgorithm 10))
;; (define id-hmacWithSHA512 (build-OID digestAlgorithm 11))

;; from NIST-AES (2.16.840.1.101.3.4.0.1)

(define aes (build-OID nistAlgorithms 1))
(define id-aes128-ECB (build-OID aes 1))
(define id-aes128-CBC (build-OID aes 2))
(define id-aes128-OFB (build-OID aes 3))
(define id-aes128-CFB (build-OID aes 4))
(define id-aes128-wrap (build-OID aes 5))
(define id-aes128-GCM (build-OID aes 6))
(define id-aes128-CCM (build-OID aes 7))
(define id-aes128-wrap-pad (build-OID aes 8))
(define id-aes192-ECB (build-OID aes 21))
(define id-aes192-CBC (build-OID aes 22))
(define id-aes192-OFB (build-OID aes 23))
(define id-aes192-CFB (build-OID aes 24))
(define id-aes192-wrap (build-OID aes 25))
(define id-aes192-GCM (build-OID aes 26))
(define id-aes192-CCM (build-OID aes 27))
(define id-aes192-wrap-pad (build-OID aes 28))
(define id-aes256-ECB (build-OID aes 41) )
(define id-aes256-CBC (build-OID aes 42)  )
(define id-aes256-OFB (build-OID aes 43) )
(define id-aes256-CFB (build-OID aes 44))
(define id-aes256-wrap (build-OID aes 45))
(define id-aes256-GCM (build-OID aes 46))
(define id-aes256-CCM (build-OID aes 47))
(define id-aes256-wrap-pad (build-OID aes 48))

(define hashAlgs (build-OID nistAlgorithms 2))

(define id-sha256 (build-OID hashAlgs 1))
(define id-sha384 (build-OID hashAlgs 2))
(define id-sha512 (build-OID hashAlgs 3))
(define id-sha224 (build-OID hashAlgs 4))
(define id-sha512-224 (build-OID hashAlgs 5))
(define id-sha512-256 (build-OID hashAlgs 6))
(define id-sha3-224 (build-OID hashAlgs 7))
(define id-sha3-256 (build-OID hashAlgs 8))
(define id-sha3-384 (build-OID hashAlgs 9))
(define id-sha3-512 (build-OID hashAlgs 10))
(define id-shake128 (build-OID hashAlgs 11))
(define id-shake256 (build-OID hashAlgs 12))
(define id-shake128-len (build-OID hashAlgs 17))
(define id-shake256-len (build-OID hashAlgs 18))

(define id-hmacWithSHA3-224 (build-OID hashAlgs 13))
(define id-hmacWithSHA3-256 (build-OID hashAlgs 14))
(define id-hmacWithSHA3-384 (build-OID hashAlgs 15))
(define id-hmacWithSHA3-512 (build-OID hashAlgs 16))

(define sigAlgs (build-OID nistAlgorithms 3))

(define id-dsa-with-sha224 (build-OID sigAlgs 1))
(define id-dsa-with-sha256 (build-OID sigAlgs 2))
(define id-dsa-with-sha384 (build-OID sigAlgs 3))
(define id-dsa-with-sha512 (build-OID sigAlgs 4))

(define id-dsa-with-sha3-224 (build-OID sigAlgs 5))
(define id-dsa-with-sha3-256 (build-OID sigAlgs 6))
(define id-dsa-with-sha3-384 (build-OID sigAlgs 7))
(define id-dsa-with-sha3-512 (build-OID sigAlgs 8))

(define id-ecdsa-with-sha3-224 (build-OID sigAlgs 9))
(define id-ecdsa-with-sha3-256 (build-OID sigAlgs 10))
(define id-ecdsa-with-sha3-384 (build-OID sigAlgs 11))
(define id-ecdsa-with-sha3-512 (build-OID sigAlgs 12))

(define id-rsassa-pkcs1-v1_5-with-sha3-224 (build-OID sigAlgs 13))
(define id-rsassa-pkcs1-v1_5-with-sha3-256 (build-OID sigAlgs 14))
(define id-rsassa-pkcs1-v1_5-with-sha3-384 (build-OID sigAlgs 15))
(define id-rsassa-pkcs1-v1_5-with-sha3-512 (build-OID sigAlgs 16))

;; from PKCS #3

(define dhKeyAgreement (build-OID pkcs-3 1))

;; from scrypt-0 (1.3.6.1.4.1.11591.4.10)

(define id-scrypt (OID 1 3 6 1 4 1 11591 4 11))

;; from PKCS5v2-1 (1.2.840.113549.1.5.16.2)

(define id-PBKDF2 (build-OID pkcs-5 12))

(define pbeWithMD2AndDES-CBC (build-OID pkcs-5 1))
(define pbeWithMD2AndRC2-CBC (build-OID pkcs-5 4))
(define pbeWithMD5AndDES-CBC (build-OID pkcs-5 3))
(define pbeWithMD5AndRC2-CBC (build-OID pkcs-5 6))
(define pbeWithSHA1AndDES-CBC (build-OID pkcs-5 10))
(define pbeWithSHA1AndRC2-CBC (build-OID pkcs-5 11))

(define id-PBES2 (build-OID pkcs-5 13))
(define id-PBMAC1 (build-OID pkcs-5 14))

(define digestAlgorithm (build-OID rsadsi 2))

(define id-hmacWithSHA1 (build-OID digestAlgorithm 7))
(define id-hmacWithSHA224 (build-OID digestAlgorithm 8))
(define id-hmacWithSHA256 (build-OID digestAlgorithm 9))
(define id-hmacWithSHA384 (build-OID digestAlgorithm 10))
(define id-hmacWithSHA512 (build-OID digestAlgorithm 11))
(define id-hmacWithSHA512-224 (build-OID digestAlgorithm 12))
(define id-hmacWithSHA512-256 (build-OID digestAlgorithm 13))

;; (define aes (build-OID nistAlgorithms 1))
(define aes128-CBC-PAD (build-OID aes 2))
(define aes192-CBC-PAD (build-OID aes 22))
(define aes256-CBC-PAD (build-OID aes 42))

;; from CMS-AEADChaCha20Poly1305 (1.2.840.113549.1.9.16.0.66)

(define id-alg-AEADChaCha20Poly1305 (build-OID pkcs-9 (smime 16) (alg 3) 18))

;; from Safecurves-pkix-18 (1.3.6.1.5.5.7.0.93)

(define id-edwards-curve-algs (OID (iso 1) (identified-organization 3) 101))
(define id-X25519 (build-OID id-edwards-curve-algs 110))
(define id-X448 (build-OID id-edwards-curve-algs 111))
(define id-Ed25519 (build-OID id-edwards-curve-algs 112))
(define id-Ed448 (build-OID id-edwards-curve-algs 113))


;; ============================================================
;; Types and Relations

;; ------------------------------------------------------------
;; PK Basic types

;; -- RSA

(define RSAPublicKey
  (SEQUENCE [modulus         INTEGER] ;; n
            [publicExponent  INTEGER])) ;; e

(define OtherPrimeInfo
  (SEQUENCE [prime             INTEGER] ;; ri
            [exponent          INTEGER] ;; di
            [coefficient       INTEGER])) ;; ti

(define OtherPrimeInfos
  (SEQUENCE-OF OtherPrimeInfo)) ;; SIZE(1..MAX)

(define RSAPrivateKey
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

;; -- DSA

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

;; -- DH

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

(define DHParameter
  (SEQUENCE [prime INTEGER]
            [base INTEGER]
            [privateValueLength INTEGER #:optional]))

;; -- EC

;; EcpkParameters = SEC1 ECDomainParameters
;; ECParameters = SEC1 SpecifiedECDomain

(define ECDSA-Sig-Value
  (SEQUENCE [r     INTEGER]
            [s     INTEGER]))

(define EcpkParameters
  (CHOICE [namedCurve    OBJECT-IDENTIFIER]
          #; [ecParameters  ECParameters]
          #; [implicitlyCA  NULL]))

(define ECPoint OCTET-STRING)

(define ECPrivateKey
  (SEQUENCE [version        INTEGER] ;; ecPrivkeyVer1
            [privateKey     OCTET-STRING]
            [parameters #:explicit 0 EcpkParameters #:optional]
            [publicKey  #:explicit 1 (BIT-STRING-containing #f) #:default #f]))

(define ecPrivkeyVer1 1)

;; -- Misc

(define Attributes (SET-OF ANY/DER))

;; ------------------------------------------------------------
;; PK Algorithm Identifiers and Relations

(define (AlgorithmIdentifier rel [typefield 'params])
  (define (get-type algorithm)
    (or (relation-ref rel 'oid algorithm typefield)
        (WRAP ANY
              #:encode (lambda (v)
                         (internal-error "unknown algorithm OID: ~e" algorithm))
              #:decode (lambda (v) 'unknown))))
  (WRAP (SEQUENCE [algorithm              OBJECT-IDENTIFIER]
                  [parameters #:dependent (get-type algorithm) #:optional])))

(define AlgorithmIdentifier/DER
  (WRAP (SEQUENCE [algorithm  OBJECT-IDENTIFIER]
                  [parameters ANY/DER #:optional])))

(define PUBKEY
  ;; for SubjectPublicKeyInfo, PrivateKeyInfo, OneAsymmetricKey
  (relation
   #:heading
   ['oid            'params           'pubkey       'privkey]
   ;; pubkey=type means BER-encode pubkey as type, then wrap in bitstring;
   ;;   #f means pubkey is bytestring (ECPoint), wrap in bitstring w/o BER
   ;;   see BIT-STRING-containing
   #:tuples
   ;; From RFC 5912:
   [rsaEncryption   NULL #|absent|#   RSAPublicKey  RSAPrivateKey]
   [id-dsa          Dss-Parms         DSAPublicKey  INTEGER]
   ;; DH: PKIX says use dhpublicnumber; OpenSSL uses PKCS#3 OID
   [dhpublicnumber  DomainParameters  DHPublicKey   INTEGER]
   [dhKeyAgreement  DHParameter       DHPublicKey   INTEGER]
   ;; Special case!: the bitstring's octets are ECPoint, not a
   ;; BER-encoding of ECPoint
   [id-ecPublicKey  EcpkParameters    #f            ECPrivateKey]

   ;; From RFC 8410:
   ;; No wrapping for public key.
   [id-Ed25519      NULL #|absent|#   #f            OCTET-STRING]
   [id-Ed448        NULL #|absent|#   #f            OCTET-STRING]
   [id-X25519       NULL #|absent|#   #f            OCTET-STRING]
   [id-X448         NULL #|absent|#   #f            OCTET-STRING]
   ))

(define CURVES
  (let ()
    (define id-brainpool
      (OID (iso 1) (identified-organization 3) (teletrust 36) (algorithm 3)
           (signature-algorithm 3) (ecSign 2) 8 1 (versionOne 1)))
    (define c-TwoCurve (build-OID ansi-X9-62 (curves 3) (characteristicTwo 0)))
    (define primeCurve (build-OID ansi-X9-62 (curves 3) (prime 1)))
    ;; Note: Names correspond with canonical names (cf catalog, curve-aliases).
    ;; References: Curves from RFC 5480 (http://www.ietf.org/rfc/rfc5480.txt)
    ;; and SEC2 (http://www.secg.org/sec2-v2.pdf).
    (relation
     #:heading
     ['name      'oid]
     #:tuples
     ;; -- Prime-order fields --
     ['secp192k1 (build-OID certicom (curve 0) 31)]
     ['secp192r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 1)]
     ['secp224k1 (build-OID certicom (curve 0) 32)]
     ['secp224r1 (build-OID certicom (curve 0) 33)]
     ['secp256k1 (build-OID certicom (curve 0) 10)]
     ['secp256r1 (build-OID ansi-X9-62 (curves 3) (prime 1) 7)]
     ['secp384r1 (build-OID certicom (curve 0) 34)]
     ['secp521r1 (build-OID certicom (curve 0) 35)]
     ;; -- Characteristic 2 fields --
     ['sect163k1 (build-OID certicom (curve 0) 1)]
     ['sect163r1 (build-OID certicom (curve 0) 2)]
     ['sect163r2 (build-OID certicom (curve 0) 15)]
     ['sect233k1 (build-OID certicom (curve 0) 26)]
     ['sect233r1 (build-OID certicom (curve 0) 27)]
     ['sect239k1 (build-OID certicom (curve 0) 3)]
     ['sect283k1 (build-OID certicom (curve 0) 16)]
     ['sect283r1 (build-OID certicom (curve 0) 17)]
     ['sect409k1 (build-OID certicom (curve 0) 36)]
     ['sect409r1 (build-OID certicom (curve 0) 37)]
     ['sect571k1 (build-OID certicom (curve 0) 38)]
     ['sect571r1 (build-OID certicom (curve 0) 39)]
     ;; Brainpool named curves
     ;; References: https://tools.ietf.org/html/rfc5639
     ['brainpoolP160r1 (build-OID id-brainpool 1)]
     ['brainpoolP160t1 (build-OID id-brainpool 2)]
     ['brainpoolP192r1 (build-OID id-brainpool 3)]
     ['brainpoolP192t1 (build-OID id-brainpool 4)]
     ['brainpoolP224r1 (build-OID id-brainpool 5)]
     ['brainpoolP224t1 (build-OID id-brainpool 6)]
     ['brainpoolP256r1 (build-OID id-brainpool 7)]
     ['brainpoolP256t1 (build-OID id-brainpool 8)]
     ['brainpoolP320r1 (build-OID id-brainpool 9)]
     ['brainpoolP320t1 (build-OID id-brainpool 10)]
     ['brainpoolP384r1 (build-OID id-brainpool 11)]
     ['brainpoolP384t1 (build-OID id-brainpool 12)]
     ['brainpoolP512r1 (build-OID id-brainpool 13)]
     ['brainpoolP512t1 (build-OID id-brainpool 14)]
     ;; Named Elliptic Curves in ANSI X9.62.
     ['c2pnb163v1 (build-OID c-TwoCurve  1)]
     ['c2pnb163v2 (build-OID c-TwoCurve  2)]
     ['c2pnb163v3 (build-OID c-TwoCurve  3)]
     ['c2pnb176w1 (build-OID c-TwoCurve  4)]
     ['c2tnb191v1 (build-OID c-TwoCurve  5)]
     ['c2tnb191v2 (build-OID c-TwoCurve  6)]
     ['c2tnb191v3 (build-OID c-TwoCurve  7)]
     ['c2onb191v4 (build-OID c-TwoCurve  8)]
     ['c2onb191v5 (build-OID c-TwoCurve  9)]
     ['c2pnb208w1 (build-OID c-TwoCurve 10)]
     ['c2tnb239v1 (build-OID c-TwoCurve 11)]
     ['c2tnb239v2 (build-OID c-TwoCurve 12)]
     ['c2tnb239v3 (build-OID c-TwoCurve 13)]
     ['c2onb239v4 (build-OID c-TwoCurve 14)]
     ['c2onb239v5 (build-OID c-TwoCurve 15)]
     ['c2pnb272w1 (build-OID c-TwoCurve 16)]
     ['c2pnb304w1 (build-OID c-TwoCurve 17)]
     ['c2tnb359v1 (build-OID c-TwoCurve 18)]
     ['c2pnb368w1 (build-OID c-TwoCurve 19)]
     ['c2tnb431r1 (build-OID c-TwoCurve 20)]
     ['prime192v1 (build-OID primeCurve  1)]
     ['prime192v2 (build-OID primeCurve  2)]
     ['prime192v3 (build-OID primeCurve  3)]
     ['prime239v1 (build-OID primeCurve  4)]
     ['prime239v2 (build-OID primeCurve  5)]
     ['prime239v3 (build-OID primeCurve  6)]
     ['prime256v1 (build-OID primeCurve  7)])))

(define (curve-oid->name oid)
  (relation-ref CURVES 'oid oid 'name))
(define (curve-name->oid name)
  (relation-ref CURVES 'name name 'oid))

;; ------------------------------------------------------------

(define AlgorithmIdentifier/PUBKEY (AlgorithmIdentifier PUBKEY))

(define SubjectPublicKeyInfo
  (SEQUENCE [algorithm AlgorithmIdentifier/PUBKEY]
            [subjectPublicKey #:dependent (SPKI-PublicKey algorithm)]))

(define (SPKI-PublicKey alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (BIT-STRING-containing (relation-ref PUBKEY 'oid alg-oid 'pubkey)))

(define PrivateKeyInfo
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier/PUBKEY]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]))

(define OneAsymmetricKey
  (SEQUENCE [version                   INTEGER]
            [privateKeyAlgorithm       AlgorithmIdentifier/PUBKEY]
            [privateKey #:dependent    (PrivateKey privateKeyAlgorithm)]
            [attributes #:implicit 0   Attributes #:optional]
            [publicKey  #:implicit 1   #:dependent (SPKI-PublicKey privateKeyAlgorithm)
                        #:default #f]))

(define (PrivateKey alg)
  (define alg-oid (hash-ref alg 'algorithm))
  (cond [(relation-ref PUBKEY 'oid alg-oid 'privkey)
         => (lambda (type)
              (WRAP OCTET-STRING
                    #:encode (lambda (v) (asn1->bytes/DER type v))
                    #:decode (lambda (v) (bytes->asn1/DER type v))))]
        [else OCTET-STRING]))


;; ------------------------------------------------------------
;; PKCS #5 Types and Relations

(define GCMParameters
  (SEQUENCE [aes-nonce          OCTET-STRING] ;; 12 octets
            [aes-ICVlen         INTEGER #:default 12]))

(define algid-hmacWithSHA1
  (hasheq 'algorithm id-hmacWithSHA1))

(define PBKDF2-PRFs
  (relation
   #:heading
   ['oid                 'params  'digest]
   #:tuples
   [id-hmacWithSHA1      NULL     'sha1]
   [id-hmacWithSHA224    NULL     'sha224]
   [id-hmacWithSHA256    NULL     'sha256]
   [id-hmacWithSHA384    NULL     'sha384]
   [id-hmacWithSHA512    NULL     'sha512]
   [id-hmacWithSHA512-224 NULL    'sha512/224]
   [id-hmacWithSHA512-256 NULL    'sha512/256]
   ;; Not "standard"!
   [id-hmacWithSHA3-224  NULL     'sha3-224]
   [id-hmacWithSHA3-256  NULL     'sha3-256]
   [id-hmacWithSHA3-384  NULL     'sha3-384]
   [id-hmacWithSHA3-512  NULL     'sha3-512]
   ))

(define PBKDF2-params
  (SEQUENCE
   [salt                OCTET-STRING] ;; actually, CHOICE with PBKDF2-SaltSources
   [iterationCount      INTEGER]
   [keyLength           INTEGER #:optional]
   [prf                 (AlgorithmIdentifier PBKDF2-PRFs)
                        #:default algid-hmacWithSHA1]))

(define scrypt-params ;; from scrypt-0
  (SEQUENCE
   [salt                OCTET-STRING]
   [costParameter       INTEGER]
   [blockSize           INTEGER]
   [parallelizationParameter INTEGER]
   [keyLength           INTEGER #:optional]))

;; -- PBES2

(define PBES2-KDFs
  (relation
   #:heading
   ['oid        'params]
   #:tuples
   [id-PBKDF2   PBKDF2-params]
   [id-scrypt   scrypt-params]))

(define PBES2-Encs
  (relation
   #:heading
   ['oid           'params       'spec]
   #:tuples
   [des-ede3-cbc   OCTET-STRING  '((des-ede3 cbc) 24)]
   [aes128-CBC-PAD OCTET-STRING  '((aes cbc) 16)]
   [aes192-CBC-PAD OCTET-STRING  '((aes cbc) 24)]
   [aes256-CBC-PAD OCTET-STRING  '((aes cbc) 32)]
   ;; Not "standard"!
   [id-aes128-GCM  GCMParameters '((aes gcm) 16)]
   [id-aes192-GCM  GCMParameters '((aes gcm) 24)]
   [id-aes256-GCM  GCMParameters '((aes gcm) 32)]
   [id-alg-AEADChaCha20Poly1305 OCTET-STRING '((chacha20-poly1305 stream) 32)]
   ))

(define PBES2-params
  (SEQUENCE
   [keyDerivationFunc   (AlgorithmIdentifier PBES2-KDFs)]
   [encryptionScheme    (AlgorithmIdentifier PBES2-Encs)]))

;; ------------------------------------------------------------
;; PKCS #8 (https://tools.ietf.org/html/rfc5208)

(define KeyEncryptionAlgorithms
  (relation
   #:heading
   ['oid        'params]
   #:tuples
   [id-PBES2    PBES2-params]))

(define EncryptedPrivateKeyInfo
  (SEQUENCE
   [encryptionAlgorithm  (AlgorithmIdentifier KeyEncryptionAlgorithms)]
   [encryptedData        OCTET-STRING]))
