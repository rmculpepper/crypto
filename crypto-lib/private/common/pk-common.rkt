;; Copyright 2013-2018 Ryan Culpepper
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
(require racket/class
         racket/match
         asn1
         binaryio/integer
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "base256.rkt"
         "../rkt/pk-asn1.rkt")
(provide (all-defined-out))

(define pk-read-key-base%
  (class* impl-base% (pk-read-key<%>)
    (super-new)

    (define/public (read-key sk fmt)
      (case fmt
        [(SubjectPublicKeyInfo)
         (-check-bytes fmt sk)
         (match (bytes->asn1/DER SubjectPublicKeyInfo sk)
           ;; Note: decode w/ type checks some well-formedness properties
           [(hash-table ['algorithm alg] ['subjectPublicKey subjectPublicKey])
            (define alg-oid (hash-ref alg 'algorithm))
            (define params (hash-ref alg 'parameters #f))
            (cond [(equal? alg-oid rsaEncryption)
                   (-decode-pub-rsa subjectPublicKey)]
                  [(equal? alg-oid id-dsa)
                   (-decode-pub-dsa params subjectPublicKey)]
                  ;; FIXME: DH support
                  [(equal? alg-oid id-ecPublicKey)
                   (-decode-pub-ec params subjectPublicKey)]
                  [(equal? alg-oid id-Ed25519)
                   (-decode-pub-eddsa 'ed25519 subjectPublicKey)]
                  [(equal? alg-oid id-Ed448)
                   (-decode-pub-eddsa 'ed448 subjectPublicKey)]
                  [else #f])]
           [_ #f])]
        [(PrivateKeyInfo OneAsymmetricKey)
         (-check-bytes fmt sk)
         (define (decode version alg privateKey publicKey)
           (define alg-oid (hash-ref alg 'algorithm))
           (define alg-params (hash-ref alg 'parameters #f))
           (cond [(equal? alg-oid rsaEncryption)
                  (-decode-priv-rsa privateKey)]
                 [(equal? alg-oid id-dsa)
                  (-decode-priv-dsa alg-params publicKey privateKey)]
                 [(equal? alg-oid id-ecPublicKey)
                  (-decode-priv-ec alg-params publicKey privateKey)]
                 [(equal? alg-oid id-Ed25519)
                  (-decode-priv-eddsa 'ed25519 publicKey privateKey)]
                 [(equal? alg-oid id-Ed448)
                  (-decode-priv-eddsa 'ed448 publicKey privateKey)]
                 [else #f]))
         (case fmt
           ;; Avoid attempting to parse the publicKey field (which could fail!)
           ;; unless OneAsymmetricKey is requested.
           [(PrivateKeyInfo)
            (match (bytes->asn1/DER PrivateKeyInfo sk)
              [(hash-table ['version version]
                           ['privateKeyAlgorithm alg]
                           ['privateKey privateKey])
               (decode version alg privateKey #f)]
              [_ #f])]
           [(OneAsymmetricKey)
            (match (bytes->asn1/DER OneAsymmetricKey sk)
              [(hash-table ['version version]
                           ['privateKeyAlgorithm alg]
                           ['privateKey privateKey]
                           ['publicKey publicKey])
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
        [(rkt) (read-rkt-key sk)]
        [else #f]))

    (define/private (read-rkt-key sk)
      (define nat? exact-nonnegative-integer?)
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match sk
        ;; Public-only keys
        [(list 'rsa 'public (? nat? n) (? nat? e))
         (-make-pub-rsa n e)]
        [(list 'dsa 'public (? nat? p) (? nat? q) (? nat? g))
         (-make-pub-dsa p q g)]
        [(list 'ec 'public (? oid? curve-oid) (? bytes? qB))
         (-make-pub-ec curve-oid qB)]
        [(list 'eddsa 'public curve (? bytes? qB))
         (-make-pub-eddsa curve qB)]
        ;; Private keys
        [(list 'rsa 'private 0 (? nat? n) (? nat? e) (? nat? d)
               (? nat? p) (? nat? q) (? nat? dp) (? nat? dq) (? nat? qInv))
         (-make-priv-rsa n e d p q dp dq qInv)]
        [(list 'dsa 'private (? nat? p) (? nat? q) (? nat? g) (? nat? y) (? nat? x))
         (-make-priv-dsa p q g y x)]
        [(list 'ec 'private (? oid? curve-oid) (? bytes? qB) (? nat? x))
         (-make-priv-ec curve-oid qB x)]
        [(list 'eddsa 'private (? symbol? curve) (? bytes? qB) (? bytes? dB))
         (-make-priv-eddsa curve qB dB)]
        [_ #f]))

    ;; ---- RSA ----

    (define/public (-decode-pub-rsa subjectPublicKey)
      (match subjectPublicKey
        [(hash-table ['modulus n] ['publicExponent e])
         (-make-pub-rsa n e)]
        [_ #f]))

    (define/public (-decode-priv-rsa privateKey)
      (match privateKey
        [(hash-table ['version 0] ;; support only two-prime keys
                     ['modulus n]
                     ['publicExponent e]
                     ['privateExponent d]
                     ['prime1 p]
                     ['prime2 q]
                     ['exponent1 dp]     ;; e * dp = 1 mod (p-1)
                     ['exponent2 dq]     ;; e * dq = 1 mod (q-1)
                     ['coefficient qInv]);; q * c = 1 mod p
         (-make-priv-rsa n e d p q dp dq qInv)]
        [_ #f]))

    (define/public (-make-pub-rsa n e) #f)
    (define/public (-make-priv-rsa n e d p q dp dq qInv) #f)

    ;; ---- DSA ----

    (define/public (-decode-pub-dsa params subjectPublicKey)
      (match params
        [(hash-table ['p p] ['q q] ['g g])
         (-make-pub-dsa p q g subjectPublicKey)]
        [_ #f]))

    (define/public (-decode-priv-dsa alg-params publicKey privateKey)
      (match alg-params
        [(hash-table ['p p] ['q q] ['g g])
         (-make-priv-dsa p q g publicKey privateKey)]
        [_ #f]))

    (define/public (-make-pub-dsa p q g y) #f)
    (define/public (-make-priv-dsa p q g y x) #f)

    ;; ---- DH ----

    ;; ---- EC ----

    (define/public (-decode-pub-ec params subjectPublicKey)
      (match params
        [`(namedCurve ,curve-oid)
         (-make-pub-ec curve-oid subjectPublicKey)]
        [_ #f]))

    (define/public (-decode-priv-ec alg-params publicKey privateKey)
      (match alg-params
        [`(namedCurve ,curve-oid)
         (match privateKey
           [(hash-table ['version 1] ['privateKey xB] ['publicKey qB])
            (-make-priv-ec curve-oid (or qB publicKey) (base256->unsigned xB))]
           [_ #f])]
        [_ #f]))

    (define/public (-make-pub-ec curve-oid qB) #f)
    (define/public (-make-priv-ec curve-oid qB x) #f)

    ;; ---- EdDSA ----

    (define/public (-decode-pub-eddsa curve qB)
      (-make-pub-eddsa curve qB))
    (define/public (-decode-priv-eddsa curve qB dB)
      (-make-priv-eddsa curve qB dB))

    (define/public (-make-pub-eddsa curve qB) #f)
    (define/public (-make-priv-eddsa curve qB dB) #f)

    ;; ----------------------------------------

    (define/public (read-params buf fmt)
      (case fmt
        [(AlgorithmIdentifier)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER AlgorithmIdentifier/DER buf)
           [(hash-table ['algorithm alg-oid] ['parameters parameters])
            (cond [(equal? alg-oid id-dsa)
                   (read-params parameters 'Dss-Parms)] ;; Dss-Parms
                  [(equal? alg-oid dhKeyAgreement)
                   (read-params parameters 'DHParameter)] ;; DHParameter
                  [(equal? alg-oid id-ecPublicKey)
                   (read-params parameters 'EcpkParameters)] ;; EcpkParameters
                  [else #f])]
           [_ #f])]
        [(DSAParameters Dss-Parms)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER Dss-Parms buf)
           [(hash-table ['p p] ['q q] ['g g])
            (-make-params-dsa p q g)]
           [_ #f])]
        [(DHParameter) ;; PKCS#3 ... not DomainParameters!
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER DHParameter buf)
           [(hash-table ['prime prime] ['base base])
            (-make-params-dh prime base)]
           [_ #f])]
        [(EcpkParameters)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER EcpkParameters)
           [(list 'namedCurve curve-oid)
            (-make-params-ec curve-oid)]
           [_ #f])]
        [(rkt) (read-rkt-params buf)]
        [else #f]))

    (define/private (read-rkt-params p)
      (define nat? exact-nonnegative-integer?)
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match p
        [(list 'dsa 'params (? nat? p) (? nat? q) (? nat? g))
         (-make-params-dsa p q g)]
        [(list 'dh 'params (? nat? prime) (? nat? base))
         (-make-params-dh prime base)]
        [(list 'ec 'params (? oid? curve-oid))
         (-make-params-ec curve-oid)]
        [_ #f]))

    (define/public (-make-params-dsa p q g) #f)
    (define/public (-make-params-dh prime base) #f)
    (define/public (-make-params-ec curve-oid) #f)

    ;; ----------------------------------------

    (define/private (-check-bytes fmt v)
      (unless (bytes? v)
        (crypto-error "bad value for key format\n  format: ~e\n  expected: bytes?\n  got: ~e"
                      fmt v)))
    ))

;; ============================================================

(define (private-key->der fmt priv pub)
  (cond [(and (eq? fmt 'OneAsymmetricKey) pub)
         (asn1->bytes/DER OneAsymmetricKey
                          (hash-set* priv 'version 1 'publicKey pub))]
        [else
         (asn1->bytes/DER PrivateKeyInfo
                          (hash-set priv 'version 0))]))

;; ---- RSA ----

(define (encode-pub-rsa fmt n e)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
              'subjectPublicKey (hasheq 'modulus n 'publicExponent e)))]
    [(rkt) (list 'rsa 'public n e)]
    [else #f]))

(define (encode-priv-rsa fmt n e d p q dp dq qInv)
  (case fmt
    [(SubjectPublicKeyInfo)
     (encode-pub-rsa fmt n e)]
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key fields
     (asn1->bytes/DER
      PrivateKeyInfo
      (hasheq 'version 0
              'privateKeyAlgorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
              'privateKey (-priv-rsa n e d p q dp dq qInv)))]
    [(RSAPrivateKey)
     (asn1->bytes/DER RSAPrivateKey (-priv-rsa n e d p q dp dq qInv))]
    [(rkt) (list 'rsa 'private 0 n e d p q dp dq qInv)]
    [else #f]))

(define (-priv-rsa n e d p q dp dq qInv)
  (hasheq 'version 0
          'modulus n
          'publicExponent e
          'privateExponent d
          'prime1 p
          'prime2 q
          'exponent1 dp
          'exponent2 dq
          'coefficient qInv))

;; ---- DSA ----

(define (encode-params-dsa fmt p q g)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier
       (hasheq 'algorithm id-dsa 'parameters (hasheq 'p p 'q q 'g g)))]
    [(DSAParameters Dss-Parms)
     (asn1->bytes/DER Dss-Parms (hasheq 'p p 'q q 'g g))]
    [(rkt) (list 'dsa 'params p q g)]
    [else #f]))

(define (encode-pub-dsa fmt p q g y)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm id-dsa 'parameters (hasheq 'p p 'q q 'g g))
              'subjectPublicKey y))]
    [(rkt) (list 'dsa 'public p q g y)]
    [else #f]))

(define (encode-priv-dsa fmt p q g y x)
  (case fmt
    [(SubjectPublicKeyInfo)
     (encode-pub-dsa fmt p q g y)]
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm id-dsa
                                           'parameters (hasheq 'p p 'q q 'g g))
              'privateKey x)
      y)]
    [(DSAPrivateKey)
     (asn1->bytes/DER
      (SEQUENCE-OF INTEGER)
      (list 0 p q g y x))]
    [(rkt) (list 'dsa 'private p q g y x)]
    [else #f]))

;; ---- DH ----

;; ---- EC ----

(define (encode-params-ec fmt curve-oid)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier
       (hasheq 'algorithm id-ecPublicKey
               'parameters (list 'namedCurve curve-oid)))]
    [(EcpkParameters)
     (asn1->bytes/DER EcpkParameters (list 'namedCurve curve-oid))]
    [(rkt) (list 'ec 'params curve-oid)]
    [else #f]))

(define (encode-pub-ec fmt curve-oid qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm id-ecPublicKey
                                 'parameters (list 'namedCurve curve-oid))
              'subjectPublicKey qB))]
    [(rkt) (list 'ec 'public curve-oid qB)]
    [else #f]))

(define (encode-priv-ec fmt curve-oid qB d)
  (case fmt
    [(SubjectPublicKeyInfo)
     (encode-pub-ec fmt curve-oid qB)]
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key
     (asn1->bytes/DER
      PrivateKeyInfo
      (hasheq 'version 0
              'privateKeyAlgorithm (hasheq 'algorithm id-ecPublicKey
                                           'parameters (list 'namedCurve curve-oid))
              'privateKey (hasheq 'version 1
                                  'privateKey (unsigned->base256 d)
                                  'publicKey qB)))]
    [(rkt) (list 'ec 'private curve-oid qB d)]
    [else #f]))

;; ---- EdDSA ----

(define (encode-priv-eddsa fmt curve qB dB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (encode-pub-eddsa fmt curve qB)]
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm (ed-curve->oid curve))
              'privateKey dB)
      qB)]
    [(rkt) (list 'eddsa 'private curve qB dB)]
    [else #f]))

(define (encode-pub-eddsa fmt curve qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm (ed-curve->oid curve))
              'subjectPublicKey qB))]
    [(rkt) (list 'eddsa 'public curve qB)]
    [else #f]))

(define (ed-curve->oid curve)
  (case curve
    [(ed25519) id-Ed25519]
    [(ed448)   id-Ed448]))

;; ----------------------------------------

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
  (define (bad) (crypto-error "failed to parse ECPoint"))
  (define buflen (bytes-length buf))
  (unless (> buflen 0) (bad))
  (case (bytes-ref buf 0)
    [(#x04) ;; uncompressed point
     (unless (odd? buflen) (bad))
     (define len (quotient (sub1 (bytes-length buf)) 2))
     (define x (bytes->integer buf #f #t 1 (+ 1 len)))
     (define y (bytes->integer buf #f #t (+ 1 len) (+ 1 len len)))
     ;; (eprintf "decode\n mlen=~v\n x=~v\n y=~v\n" len x y)
     (cons x y)]
    [else (bad)]))

;; curve-oid->name : OID -> Symbol/#f
(define (curve-oid->name oid)
  (for/first ([entry (in-list known-curves)]
              #:when (equal? (cdr entry) oid))
    (car entry)))

;; curve-name->oid : Symbol -> OID/#f
(define (curve-name->oid name)
  (cond [(assq name known-curves) => cdr] [else #f]))
