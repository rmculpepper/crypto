#lang racket/base
(require "syntax.rkt" "types.rkt")
(provide (all-defined-out))

(define DsaSig (Sequence [r INTEGER] [s INTEGER]))

(define pkcs1 '((iso 1) (member-body 2) (us 840) (rsadsi 113549) (pkcs 1) 1))

(define rsaEncryption (append pkcs1 '(1)))

(define RSAPublicKey (Sequence [modulus INTEGER] [publicExponent INTEGER]))

;; ---

(define-asn1-type ECDomainParameters
  (Choice [ecParameters ECParameters]
          [namedCurve OBJECT-IDENTIFIER]
          [implicitlyCA NULL]))

(define-asn1-type ECParameters
  (Sequence [version   ECPVer]
            [field     FieldID]
            [curve     Curve]
            [base      ECPoint]
            [order     INTEGER]
            [cofactor  INTEGER #:optional]))

(define-asn1-type FieldID
  (Sequence [fieldType OBJECT-IDENTIFIER]
            [parameters ANY]))

(define-asn1-type ECPVer INTEGER)

(define-asn1-type Curve
  [Sequence [a FieldElement]
            [b FieldElement]
            [seed BIT-STRING #:optional]])

(define-asn1-type FieldElement OCTET-STRING)

(define-asn1-type ECPoint OCTET-STRING)

(DER-decode-hooks
 (list (list ANY 'pre (lambda (t b) (list 'ANY b)))))
