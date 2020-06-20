#lang racket/base
(require racket/contract
         racket/match
         base64)
(provide (contract-out
          #:unprotected-submodule unchecked
          [read-pem
           (->* [input-port?]
                [(-> bytes? any)
                 #:only (or/c #f (listof bytes?))
                 #:who symbol?]
                (or/c eof-object? (cons/c bytes? any/c)))]))

;; This is not the original PEM; it is the PEM-inspired "textual
;; encoding" described in RFC 7468 for the purpose of encoding
;; cryptographic keys, certificates, etc.

;; Reference: https://tools.ietf.org/html/rfc7468

;; read-pem : InputPort (Bytes -> X) #:only (U #f (Listof Bytes))
;;         -> (U EOF (cons Bytes X))
;; Note: skips forward until a beginning "encapsulation boundary";
;; consumes blanks and one line terminator after the ending boundary.
;; Raises an error if the end boundary is missing or has a different label.
(define (read-pem in [decode base64-decode] #:only [only #f] #:who [who 'read-pem])
  (define begin-rx
    #px#"(?m:^-{5}BEGIN ([\x21-\x2C\x2E-\x7E][\x20-\x7E]*)-{5}[[:blank:]]*(?:\r|\n|\r\n)?)")
  (define end-rx
    #px#"(?m:^-{5}END ([\x21-\x2C\x2E-\x7E][\x20-\x7E]*)-{5}[[:blank:]]*(?:\r|\n|\r\n)?)")
  (let loop ()
    (match (regexp-match begin-rx in)
      [(list _ label1)
       (define out (open-output-bytes))
       (match (regexp-match end-rx in 0 #f out)
         [(list _ label2)
          (unless (equal? label1 label2)
            (error who "END label does not match BEGIN\n  begin: ~s\n  end: ~s"
                   label1 label2))
          (cond [(or (not only) (member label1 only))
                 (cons label1 (decode (get-output-bytes out)))]
                [else (loop)])]
         [#f (error who "incomplete PEM ~e content" label1)])]
      [#f eof])))
