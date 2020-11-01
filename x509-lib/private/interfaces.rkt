#lang racket/base
(require racket/class)
(provide (all-defined-out))

(define certificate-data<%>
  (interface*
   ()
   ([prop:equal+hash
     (list (lambda (self other recur) (send self equal-to other recur))
           (lambda (self recur) (send self hash-code recur))
           (lambda (self recur) (send self hash-code recur)))]
    [prop:custom-write
     (lambda (self out mode) (send self custom-write out mode))])
   equal-to
   hash-code
   custom-write

   get-der
   get-cert-signature-alg
   get-cert-signature-bytes

   get-version
   get-serial-number
   get-signature-alg
   get-issuer
   get-validity
   get-subject
   get-spki
   get-issuer-unique-id
   get-subject-unique-id
   get-extensions

   is-CA?
   is-CRL-issuer?
   is-self-issued?
   is-self-signed?
   get-key-uses

   get-extension
   get-extension-value

   get-name-constraints
   get-subject-alt-name
   get-validity-seconds
   ))

(define certificate<%>
  (interface (certificate-data<%>)
    ))

(define certificate-chain<%>
  (interface*
   ()
   ([prop:custom-write
     (lambda (self out mode) (send self custom-write out mode))])
   custom-write
   ))

;; Note: for documentation; not actually implemented
(define trust-anchor<%>
  (interface ()
    get-pk
    get-subject
    ))

(define x509-lookup<%>
  (interface ()
    trust?            ;; Certificate -> Boolean
    lookup-by-subject ;; Name -> (Listof Certificate)
    ))

(define certificate-store<%>
  (interface (x509-lookup<%>)
    add                       ;; <kw args> -> Store
    add-trusted-from-pem-file ;; Path/String -> Store
    ))

(define-logger x509)

(define (certificate? v) (is-a? v certificate<%>))
(define (certificate-chain? v) (is-a? v certificate-chain<%>))
(define (certificate-store? v) (is-a? v certificate-store<%>))

(struct exn:x509 exn:fail () #:transparent)
(struct exn:x509:certificate exn:x509 (errors) #:transparent)
(struct exn:x509:chain exn:x509 (errors) #:transparent)

;; An ErrorList is a list of "error description" values.
;; The empty list means no errors were detected.
