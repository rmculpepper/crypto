;; Copyright 2020 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require asn1 asn1/util/names)
(provide (all-defined-out))

;; Translation of "ocsp.asn1"

;; module OCSP-2013-88
(require (only-in "asn1.rkt"
                  AuthorityInfoAccessSyntax
                  CRLReason
                  GeneralName
                  Name
                  CertificateSerialNumber
                  Extensions
                  id-kp
                  id-ad-ocsp
                  Certificate
                  SIGNING)
         (only-in crypto/private/common/asn1
                  ANY/DER
                  AlgorithmIdentifier))

;; Value, etc definitions
(define v1 0)
;;(define id-kp-OCSPSigning (build-OID id-kp 9))
(define id-pkix-ocsp (build-OID id-ad-ocsp))
(define id-pkix-ocsp-basic (build-OID id-pkix-ocsp 1))
(define id-pkix-ocsp-nonce (build-OID id-pkix-ocsp 2))
(define id-pkix-ocsp-crl (build-OID id-pkix-ocsp 3))
(define id-pkix-ocsp-response (build-OID id-pkix-ocsp 4))
(define id-pkix-ocsp-nocheck (build-OID id-pkix-ocsp 5))
(define id-pkix-ocsp-archive-cutoff (build-OID id-pkix-ocsp 6))
(define id-pkix-ocsp-service-locator (build-OID id-pkix-ocsp 7))
(define id-pkix-ocsp-pref-sig-algs (build-OID id-pkix-ocsp 8))
(define id-pkix-ocsp-extended-revoke (build-OID id-pkix-ocsp 9))

;; Type definitions
(define-asn1-type OCSPRequest
  (SEQUENCE (tbsRequest TBSRequest) (optionalSignature #:explicit 0 Signature #:optional)))
(define-asn1-type TBSRequest
  (SEQUENCE
   (version #:explicit 0 Version #:default v1)
   (requestorName #:explicit 1 GeneralName #:optional)
   (requestList (SEQUENCE-OF Request))
   (requestExtensions #:explicit 2 Extensions #:optional)))
(define-asn1-type Signature
  (SEQUENCE
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)
   (certs #:explicit 0 (SEQUENCE-OF Certificate) #:optional)))
(define-asn1-type Version INTEGER)
(define-asn1-type Request
  (SEQUENCE (reqCert CertID) (singleRequestExtensions #:explicit 0 Extensions #:optional)))
(define-asn1-type CertID
  (SEQUENCE
   (hashAlgorithm (AlgorithmIdentifier HASH-ALGS))
   (issuerNameHash OCTET-STRING)
   (issuerKeyHash OCTET-STRING)
   (serialNumber CertificateSerialNumber)))

(define-asn1-type OCSPResponse
  (SEQUENCE
   (responseStatus OCSPResponseStatus)
   (responseBytes #:explicit 0 ResponseBytes #:optional)))
(define-asn1-type OCSPResponseStatus
  (WRAP-NAMES
   ENUMERATED
   (list
    (cons 'successful 0)
    (cons 'malformedRequest 1)
    (cons 'internalError 2)
    (cons 'tryLater 3)
    (cons 'sigRequired 5)
    (cons 'unauthorized 6))))
(define-asn1-type ResponseBytes
  (SEQUENCE (responseType OBJECT-IDENTIFIER)
            (response #:dependent
                      (OCTET-STRING-containing
                       (relation-ref RESPONSE 'oid responseType 'type)))))
(define-asn1-type BasicOCSPResponse
  (SEQUENCE
   (tbsResponseData ResponseData)
   (signatureAlgorithm (AlgorithmIdentifier SIGNING))
   (signature BIT-STRING)
   (certs #:explicit 0 (SEQUENCE-OF ANY/DER #|Certificate|#) #:optional)))
(define-asn1-type ResponseData
  (SEQUENCE
   (version #:explicit 0 Version #:default v1)
   (responderID ResponderID)
   (producedAt GeneralizedTime)
   (responses (SEQUENCE-OF SingleResponse))
   (responseExtensions #:explicit 1 Extensions #:optional)))
(define-asn1-type ResponderID
  (CHOICE (byName #:explicit 1 Name) (byKey #:explicit 2 KeyHash)))
(define-asn1-type KeyHash OCTET-STRING)
(define-asn1-type SingleResponse
  (SEQUENCE
   (certID CertID)
   (certStatus CertStatus)
   (thisUpdate GeneralizedTime)
   (nextUpdate #:explicit 0 GeneralizedTime #:optional)
   (singleExtensions #:explicit 1 Extensions #:optional)))
(define-asn1-type CertStatus
  (CHOICE
   (good #:implicit 0 NULL)
   (revoked #:implicit 1 RevokedInfo)
   (unknown #:implicit 2 UnknownInfo)))
(define-asn1-type RevokedInfo
  (SEQUENCE
   (revocationTime GeneralizedTime)
   (revocationReason #:explicit 0 CRLReason #:optional)))
(define-asn1-type UnknownInfo NULL)
(define-asn1-type ArchiveCutoff GeneralizedTime)
(define-asn1-type AcceptableResponses (SEQUENCE-OF OBJECT-IDENTIFIER))
(define-asn1-type ServiceLocator (SEQUENCE (issuer Name) (locator AuthorityInfoAccessSyntax)))
(define-asn1-type CrlID
  (SEQUENCE
   (crlUrl #:explicit 0 IA5String #:optional)
   (crlNum #:explicit 1 INTEGER #:optional)
   (crlTime #:explicit 2 GeneralizedTime #:optional)))
(define-asn1-type PreferredSignatureAlgorithms (SEQUENCE-OF PreferredSignatureAlgorithm))
(define-asn1-type PreferredSignatureAlgorithm
  (SEQUENCE
   (sigIdentifier (AlgorithmIdentifier SIGNING))
   (certIdentifier (AlgorithmIdentifier SIGNING) #:optional)))

;; ============================================================

(require (only-in crypto/private/common/asn1
                  relation
                  relation-ref
                  OCTET-STRING-containing
                  id-sha1
                  id-sha256))
(provide id-sha1 id-sha256)

(define HASH-ALGS
  (relation
   #:heading
   ['oid                    'params]
   #:tuples
   [id-sha1                 NULL]
   [id-sha256               NULL]))

(define RESPONSE
  (relation
   #:heading
   ['oid                 'type]
   #:tuples
   [id-pkix-ocsp-basic   BasicOCSPResponse]))
