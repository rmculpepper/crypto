#lang racket/base
(require racket/contract/base
         "private/interfaces.rkt"
         "private/cert.rkt"
         "private/store.rkt")
(provide certificate<%>
         certificate-chain<%>
         certificate-store<%>
         certificate?
         certificate-chain?
         certificate-store?
         (struct-out exn:x509)
         (struct-out exn:x509:certificate)
         (struct-out exn:x509:chain)

         (contract-out
          [bytes->certificate
           (-> bytes? certificate?)]
          [read-pem-certificates
           (->* [input-port?] [#:count (or/c exact-nonnegative-integer? +inf.0)]
                (listof certificate?))]
          [pem-file->certificates
           (->* [path-string?] [#:count (or/c exact-nonnegative-integer? +inf.0)]
                (listof certificate?))])

         empty-certificate-store)
