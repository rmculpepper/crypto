#lang racket/base
(require racket/list
         racket/system
         racket/string
         crypto crypto/all
         racket/class
         racket/pretty
         "private/x509/interfaces.rkt"
         "private/x509/validation.rkt")
(provide (all-defined-out))

;; Testing setup:
;; - ca-key.pem - private key for CA
;; - ca-cert.pem - self-signed cert for CA
;; - ca-alt-{key,cert}.pem - different key, cert for CA (same subject name!)
;; - ca2-{key,cert}.pem - key and cert for CA w/ different subject name
;; - mid-ca-{key,cert}.pem - key and cert for intermediate CA
;; - end-{key,cert}.pem - correctly signed end cert
;;   - probably want lots of variations w/ wildcards, etc

(define (openssl . args)
  (define (to-string x) (if (path? x) (path->string x) x))
  (let ([args (flatten args)])
    (eprintf "$ openssl ~a\n" (string-join (map to-string args) " "))
    (void (or (apply system* (find-executable-path "openssl") args)
              (error 'openssl "command failed")))))
(define (openssl-req . args) (apply openssl "req" args))
(define (openssl-x509 . args) (apply openssl "x509" args))
(define (openssl-genrsa . args) (apply openssl "genrsa" args))

(define (key-file name) (format "~a.key" name))
(define (cert-file name) (format "~a-cert.pem" name))
(define (csr-file name) (format "~a.csr" name))
(define (srl-file name) (format "~a.srl" name))
(define (ext-file name) (format "~a.ext" name))

(define (dn->string dn)
  (cond [(string? dn) dn]
        [else (string-append "/" (string-join dn "/") "/")]))

;; ----

(define (make-root-ca name dn)
  (unless (file-exists? (key-file name))
    (openssl-genrsa "-out" (key-file name) "2048"))
  (openssl-req "-x509" "-new" "-key" (key-file name)
               "-sha256" "-days" "200" "-out" (cert-file name)
               "-subj" (dn->string dn)))

(define (make-int-ca ca-name name dn)
  (unless (file-exists? (key-file name))
    (openssl-genrsa "-out" (key-file name) "2048"))
  (with-output-to-file (ext-file name) #:exists 'replace
    (lambda ()
      (printf "authorityKeyIdentifier=keyid,issuer\n")
      (printf "basicConstraints=CA:TRUE\n")))
  (openssl-req "-new" "-key" (key-file name) "-out" (csr-file name)
               "-subj" (dn->string dn))
  (openssl-x509 "-req" "-in" (csr-file name) (CA-args ca-name)
                "-out" (cert-file name) "-days" "100" "-sha256"
                "-extfile" (ext-file name)))

(define (CA-args ca-name)
  (list "-CA" (cert-file ca-name) "-CAkey" (key-file ca-name) "-CAcreateserial"))

(define (make-end ca-name name dn [dnsnames null])
  (unless (file-exists? (key-file name))
    (openssl-genrsa "-out" (key-file name) "2048"))
  (openssl-req "-new" "-key" (key-file name) "-subj" (dn->string dn)
               "-out" (csr-file name))
  (with-output-to-file (ext-file name) #:exists 'replace
    (lambda ()
      (printf "authorityKeyIdentifier=keyid,issuer\n")
      (printf "basicConstraints=CA:FALSE\n")
      (printf "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment\n")
      (printf "subjectAltName=@alt_names\n\n")
      (printf "[alt_names]\n")
      (for ([dnsname dnsnames] [i (in-naturals 1)])
        (printf "DNS.~a=~a\n" i dnsname))))
  (openssl-x509 "-req" "-in" (csr-file name) (CA-args ca-name)
                "-out" (cert-file name) "-days" "30" "-sha256"
                "-extfile" (ext-file name)))

;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

(pretty-print-columns 160)
(crypto-factories libcrypto-factory)

;; read-chain : Path ... -> certificate-chain%
(define (read-chain . files)
  (define certs (append* (map read-certs files)))
  ;; Build chain for
  ;; - first non-CA cert in the list, if one exists
  ;; - the first cert, otherwise
  (define end-cert
    (or (for/first ([cert certs] #:when (not (send cert is-CA?))) cert)
        (car certs)))
  (build-chain end-cert certs #:store (current-x509-store)))

;; XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

(define ((chain-exn? errors) v)
  (and (exn:x509:chain? v)
       (for/and ([err errors])
         (member err (exn:x509:chain-errors v)))
       #t))

(define (certificate? x) (is-a? x certificate<%>))
(define (certificate-chain? x) (is-a? x certificate-chain<%>))

(module+ main
  (require rackunit)

  (define ca-name '("O=testing" "CN=testing-ca"))
  (make-root-ca "ca" ca-name)

  (define intca-name '("O=testing" "CN=testing-int-ca"))
  (make-int-ca "ca" "intca" intca-name)

  (define end-name '("C=US" "ST=MA" "L=Boston" "CN=end.test.com"))
  (define end-dnsnames '("end.test.com" "alt.test.com"))
  (make-end "intca" "end" end-name end-dnsnames)

  (current-x509-store
   (send empty-x509-store add
         #:stores (list (x509-store:trusted-pem-file (cert-file "ca")))))

  (test-case "intca"
    (check-pred certificate-chain?
                (read-chain (cert-file "intca"))))
  (test-case "end w/o intca"
    (check-exn exn:x509:chain?
               (lambda () (read-chain (cert-file "end")))))
  (test-case "end w/ intca"
    (check-pred certificate-chain?
                (read-chain (cert-file "end") (cert-file "intca"))))

  (make-root-ca "fakeca" ca-name) ;; impersonates "ca"
  (make-int-ca "fakeca" "fakeintca" intca-name) ;; impersonates "intca"
  (make-end "fakeintca" "fakeend" end-name end-dnsnames) ;; impersonates "end"

  (test-case "fakeend"
    ;; Cannot build chain w/o "fakeintca" or "intca":
    (check-exn (chain-exn? '(incomplete))
               (lambda () (read-chain (cert-file "fakeend")))))
  (test-case "fakeintca"
    ;; Since "fakeca" has same Subject as "ca", will build chain with "ca",
    ;; but signature verification will fail.
    (check-exn (chain-exn? '((1 . bad-signature)))
               (lambda () (read-chain (cert-file "fakeintca"))))
    (check-exn (chain-exn? '((1 . bad-signature)))
               (lambda () (read-chain (cert-file "fakeend") (cert-file "fakeintca")))))
  (test-case "fakeend w/ intca"
    ;; Similar, but fakeend issuer matches intca.
    (check-exn (chain-exn? '((2 . bad-signature)))
               (lambda () (read-chain (cert-file "fakeend") (cert-file "intca")))))
  )
