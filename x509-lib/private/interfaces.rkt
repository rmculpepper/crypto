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
  (interface ()))

;; Note: for documentation; not actually implemented
(define trust-anchor<%>
  (interface ()
    get-pk
    get-subject
    ))
