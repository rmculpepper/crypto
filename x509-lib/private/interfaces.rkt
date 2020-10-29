#lang racket/base
(require racket/class)
(provide (all-defined-out))


(define certificate<%>
  (interface*
   ()
   ([prop:equal+hash
     (list (lambda (self other recur) (send self equal-to other recur))
           (lambda (self recur) (send self hash-code recur))
           (lambda (self recur) (send self hash-code recur)))])
   equal-to
   hash-code))

(define certificate-chain<%>
  (interface ()))


;; Note: for documentation; not actually implemented
(define trust-anchor<%>
  (interface ()
    get-pk
    get-subject
    ))
