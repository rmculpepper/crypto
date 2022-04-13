#lang racket/base
(require rackunit
         racket/match
         racket/file
         racket/class
         scramble/result
         crypto crypto/all
         x509
         (submod "test.rkt" util))
(provide (all-defined-out))

(define CRL? #t)

(crypto-factories libcrypto-factory)

(define good-dir (build-path working-dir "good"))
(define bad-dir (build-path working-dir "bad"))
(for-each make-directory* (list good-dir bad-dir))

(define (fetch-certs host)
  (unless (file-exists? host)
    (eprintf "Fetching ~s\n" host)
    (call-with-output-file* host #:exists 'replace
      (lambda (out)
        (parameterize ((current-input-port (open-input-bytes #"")))
          (define logs (openssl "s_client" "-connect" (format "~a:443" host) "-showcerts"))
          (eprintf "GOT ~e\n" logs)
          (write-string logs out))))))

(define ((chain-exn? errors) v)
  (and (exn:x509:chain? v)
       (for/and ([err errors])
         (member err (exn:x509:chain-errors v)))
       #t))

(define good-sites
  '("google.com"
    "microsoft.com"
    "racket-lang.org"
    "wikipedia.org"))

(define bad-sites
  '(["expired.badssl.com" chain]
    ["wrong.host.badssl.com" tls]
    ["self-signed.badssl.com" chain]
    ["untrusted-root.badssl.com" chain]
    ["revoked.badssl.com" revoked]))

(parameterize ((current-directory good-dir))
  (for-each fetch-certs good-sites))

(parameterize ((current-directory bad-dir))
  (for-each fetch-certs (map car bad-sites)))

(define store (send (empty-certificate-store)
                    add-trusted-from-openssl-directory "/etc/ssl/certs"))

(define rev-db (build-path working-dir "revocations.db"))
(define rev (make-revocation-checker rev-db))
(define urev (make-revocation-checker rev-db #:trust-db? #f))

(for ([site good-sites])
  (test-case (format "good: ~a" site)
    (define c (send store pem-file->chain (build-path good-dir site)))
    (check-equal? (send rev check-ocsp c) (ok #t))
    (check-equal? (send urev check-ocsp c) (ok #t))
    (when CRL?
      (check-equal? (send rev check-crl c) (ok #t))
      (check-equal? (send urev check-crl c) (ok #t)))
    (void)))

(for ([site+fail bad-sites])
  (match-define (list site fail) site+fail)
  (test-case (format "bad: ~a" site)
    (define (get-chain) (send store pem-file->chain (build-path bad-dir site)))
    (define c
      (case fail
        [(chain) (check-exn (chain-exn? '()) get-chain) #f]
        [else (get-chain)]))
    (define tls-result (and c (send c check-suitable-for-tls-server site)))
    (case fail
      [(chain) (void)]
      [(tls) (check-pred bad? tls-result)]
      [else (check-pred ok? tls-result)])
    (case fail
      [(chain) (void)]
      [(revoked)
       (check-equal? (send rev check-ocsp c) (bad 'revoked))
       (check-equal? (send urev check-ocsp c) (bad 'revoked))
       (when CRL?
         (check-equal? (send rev check-crl c) (bad 'revoked))
         (check-equal? (send urev check-crl c) (bad 'revoked)))]
      [else
       (check-equal? (send rev check-ocsp c) (ok #t))
       (check-equal? (send urev check-ocsp c) (ok #t))
       (when CRL?
         (check-equal? (send rev check-crl c) (ok #t))
         (check-equal? (send urev check-crl c) (ok #t)))])
    (void)))
