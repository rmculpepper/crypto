#lang racket/base
(require crypto crypto/all
         racket/string
         racket/list
         racket/class
         racket/pretty
         "x509.rkt")
(provide (all-defined-out))

(module util racket/base
  (require racket/runtime-path
           racket/string
           racket/system
           racket/list
           racket/file)
  (provide (all-defined-out))

  (define-runtime-path working-dir "test-scratch")
  (make-directory* working-dir)
  (current-directory working-dir)

  (define (openssl . args)
    (define (to-string x) (if (path? x) (path->string x) x))
    (let ([args (flatten args)])
      (printf "$ openssl ~a\n" (string-join (map to-string args) " "))
      (define out (open-output-string))
      (define ok? (parameterize ((current-output-port out)
                                 (current-error-port out))
                    (apply system* (find-executable-path "openssl") args)))
      (cond [ok? (get-output-string out)]
            [else
             (printf "~a\n" (get-output-string out))
             (error 'openssl "command failed")])))
  (define (openssl-req . args) (void (apply openssl "req" args)))
  (define (openssl-x509 . args) (void (apply openssl "x509" args)))
  (define (openssl-genrsa . args) (void (apply openssl "genrsa" args)))

  (define (key-file name) (format "~a.key" name))
  (define (cert-file name) (format "~a-cert.pem" name))
  (define (csr-file name) (format "~a.csr" name))
  (define (srl-file name) (format "~a.srl" name))
  (define (ext-file name) (format "~a.ext" name)))
(require 'util)

;; ----

(define (make-root-ca name dn)
  (unless (file-exists? (key-file name))
    (openssl-genrsa "-out" (key-file name) "2048"))
  (openssl-req "-x509" "-new" "-key" (key-file name)
               "-sha256" "-days" "200" "-out" (cert-file name)
               "-subj" (dn->string dn)
               "-addext" "keyUsage=critical,keyCertSign"))

(define (make-int-ca ca-name name dn
                     #:permit-names [permit-names null]
                     #:exclude-names [exclude-names null])
  (unless (file-exists? (key-file name))
    (openssl-genrsa "-out" (key-file name) "2048"))
  (with-output-to-file (ext-file name) #:exists 'replace
    (lambda ()
      (printf "authorityKeyIdentifier=keyid,issuer\n")
      (printf "basicConstraints=critical,CA:TRUE\n")
      (printf "subjectKeyIdentifier=hash\n")
      (printf "keyUsage=critical,keyCertSign\n")
      (when (or (pair? permit-names) (pair? exclude-names))
        (printf "nameConstraints=critical,@nc_section\n")
        (printf "[nc_section]\n")
        (for ([i (in-naturals 1)] [permit (in-list permit-names)])
          (printf "permitted;~a.~a=~a\n" (car permit) i (cadr permit)))
        (for ([i (in-naturals 1)] [exclude (in-list exclude-names)])
          (printf "excluded;~a.~a=~a\n" (car exclude) i (cadr exclude))))))
  (openssl-req "-new" "-key" (key-file name) "-out" (csr-file name)
               "-subj" (dn->string dn))
  (openssl-x509 "-req" "-in" (csr-file name) (CA-args ca-name)
                "-out" (cert-file name) "-days" "100" "-sha256"
                "-extfile" (ext-file name)))

(define (CA-args ca-name)
  (list "-CA" (cert-file ca-name) "-CAkey" (key-file ca-name) "-CAcreateserial"))

(define (make-end ca-name name dn [dnsnames null]
                  #:key-file [keyfile (key-file name)])
  (unless (file-exists? keyfile)
    (openssl-genrsa "-out" keyfile "2048"))
  (openssl-req "-new" "-key" keyfile "-subj" (dn->string dn)
               "-out" (csr-file name))
  (with-output-to-file (ext-file name) #:exists 'replace
    (lambda ()
      (printf "authorityKeyIdentifier=keyid,issuer\n")
      (printf "basicConstraints=critical,CA:FALSE\n")
      (printf "keyUsage=critical,~a\n"
              "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment")
      (when (pair? dnsnames)
        (printf "subjectAltName=@alt_names\n\n")
        (printf "[alt_names]\n")
        (for ([dnsname dnsnames] [i (in-naturals 1)])
          (printf "DNS.~a=~a\n" i dnsname)))))
  (openssl-x509 "-req" "-in" (csr-file name) (CA-args ca-name)
                "-out" (cert-file name) "-days" "30" "-sha256"
                "-extfile" (ext-file name)))

(define (dn->string dn)
  (cond [(string? dn) dn]
        [else (string-append "/" (string-join dn "/") "/")]))

;; ============================================================

(pretty-print-columns 160)
(crypto-factories libcrypto-factory)

;; read-chain : Path ... -> certificate-chain%
(define (read-chain . files)
  (cond [(= (length files) 1)
         (send (current-x509-store) pem-file->chain (car files) ((current-get-valid-time)))]
        [else
         (define certs (append* (map pem-file->certificates files)))
         (define end-cert (car certs))
         (send (current-x509-store) build-chain end-cert certs ((current-get-valid-time)))]))

(define current-x509-store (make-parameter (empty-certificate-store)))
(define current-get-valid-time (make-parameter current-seconds))

;; ============================================================

(define ((chain-exn? errors) v)
  (and (exn:x509:chain? v)
       (for/and ([err errors])
         (member err (exn:x509:chain-errors v)))
       #t))

(module+ main
  (require rackunit)

  (define ca-name '("O=testing" "CN=testing-ca"))
  (make-root-ca "ca" ca-name)

  (define intca-name '("O=testing" "CN=testing-int-ca"))
  (make-int-ca "ca" "intca" intca-name
               #:permit-names '((DNS "test.com"))
               #:exclude-names '((DNS "special.test.com")))

  (define end-name '("C=US" "ST=MA" "L=Boston" "CN=end.test.com"))
  (define end-dnsnames '("end.test.com" "alt.test.com"))
  (make-end "intca" "end" end-name end-dnsnames)

  (current-x509-store
   (send (current-x509-store) add-trusted-from-pem-file (cert-file "ca")))

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
    (check-exn (chain-exn? '((1 . signature:bad)))
               (lambda () (read-chain (cert-file "fakeintca"))))
    (check-exn (chain-exn? '((1 . signature:bad)))
               (lambda () (read-chain (cert-file "fakeend") (cert-file "fakeintca")))))
  (test-case "fakeend w/ intca"
    ;; Similar, but fakeend issuer matches intca.
    (check-exn (chain-exn? '((2 . signature:bad)))
               (lambda () (read-chain (cert-file "fakeend") (cert-file "intca")))))

  ;; ----------------------------------------

  ;; 6.1.3.a.1 signature valid -- tested above
  ;; 6.1.3.a.2 validity period
  (test-case "valid-time"
    ;; Since we just built the certs, should not be valid last year
    (parameterize ((current-get-valid-time
                    (lambda () (- (current-seconds) (* 365 24 60 60)))))
      (check-exn (chain-exn? '((1 . validity-period:not-contained)))
                 (lambda () (read-chain (cert-file "intca"))))
      (check-exn (chain-exn? '((1 . validity-period:not-contained)))
                 (lambda () (read-chain (cert-file "end") (cert-file "intca")))))
    ;; Should not be valid in 5 years (see -days arguments above)
    (parameterize ((current-get-valid-time
                    (lambda () (+ (current-seconds) (* 5 365 24 60 60)))))
      (check-exn (chain-exn? '((1 . validity-period:not-contained)))
                 (lambda () (read-chain (cert-file "intca"))))
      (check-exn (chain-exn? '((1 . validity-period:not-contained)))
                 (lambda () (read-chain (cert-file "end") (cert-file "intca"))))))
  ;; 6.1.3.a.3 not revoked -- not supported
  ;; 6.1.3.a.4 issuer matches
  (test-case "issuer mismatch"
    ;; build-chains uses issuer name to build, so construct bad chain manually
    (define certs (append (pem-file->certificates (cert-file "ca"))
                          (pem-file->certificates (cert-file "end"))))
    (check-exn (chain-exn? '((1 . issuer:name-mismatch)))
               (lambda ()
                 (send (current-x509-store) check-chain certs))))
  ;; 6.1.3.{b,c} name constraints
  (test-case "name constraints"
    (make-end "intca" "cz-end" '("C=CZ" "L=Praha" "CN=test.cz") '("test.cz"))
    (check-exn (chain-exn? '((2 1 . name-constraints:subjectAltName-rejected)))
               (lambda () (read-chain (cert-file "cz-end") (cert-file "intca"))))
    (make-end "intca" "special-end" '("CN=special.test.com") '("special.test.com"))
    (check-exn (chain-exn? '((2 1 . name-constraints:subjectAltName-rejected)))
               (lambda () (read-chain (cert-file "special-end") (cert-file "intca")))))
  ;; 6.1.3.{d-f} policies -- not unsupported
  ;; 6.1.4.{a-j} nothing to do
  ;; 6.1.4.k intermediate is CA
  (test-case "intermediate is CA"
    (make-end "ca" "intca-as-end" intca-name '("intca.org")
              #:key-file (key-file "intca"))
    (define certs (append (pem-file->certificates (cert-file "ca"))
                          (pem-file->certificates (cert-file "intca-as-end"))
                          (pem-file->certificates (cert-file "end"))))
    (check-exn (chain-exn? '((1 . intermediate:not-CA)
                             (1 . intermediate:missing-keyCertSign)))
               (lambda ()
                 (send (current-x509-store) check-chain certs))))
  ;; 6.1.4.m intermediate: path length constraint -- TODO
  ;; 6.1.4.n intermediate: keyCertSign -- see 6.1.4.k
  ;; 6.1.5.{a,b,g} -- policies not supported
  ;; 6.1.5.{c-e} signature -- tested above
  ;; 6.1.5.f critical extensions -- TODO
  )

(module+ test
  (require (submod ".." main)))
