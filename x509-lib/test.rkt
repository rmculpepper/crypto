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
    (eprintf "$ ~a\n" (string-join (map to-string args) " "))
    (apply system* (find-executable-path "openssl") args)))
(define (openssl-req . args) (apply openssl "req" args))
(define (openssl-x509 . args) (apply openssl "x509" args))
(define (openssl-genrsa . args) (apply openssl "genrsa" args))

(define (key-file name) (format "~a.key" name))
(define (cert-file name) (format "~a-cert.pem" name))
(define (csr-file name) (format "~a.csr" name))
(define (srl-file name) (format "~a.srl" name))
(define (ext-file name) (format "~a.ext" name))

;; ----

(define (make-root-ca name dn)
  (openssl-genrsa "-out" (key-file name) "2048")
  (openssl-req "-x509" "-new" "-key" (key-file name)
               "-sha256" "-days" "200" "-out" (cert-file name)
               "-subj" dn))

(define (make-int-ca ca-name name dn)
  (openssl-genrsa "-out" (key-file name) "2048")
  (with-output-to-file (ext-file name) #:exists 'replace
    (lambda ()
      (printf "authorityKeyIdentifier=keyid,issuer\n")
      (printf "basicConstraints=CA:TRUE\n")))
  (openssl-req "-new" "-key" (key-file name) "-out" (csr-file name)
               "-subj" dn)
  (openssl-x509 "-req" "-in" (csr-file name) (CA-args ca-name)
                "-out" (cert-file name) "-days" "100" "-sha256"
                "-extfile" (ext-file name)))

(define (CA-args ca-name)
  (list "-CA" (cert-file ca-name) "-CAkey" (key-file ca-name) "-CAcreateserial"))

(define (make-end ca-name name dn dnsnames)
  (openssl-genrsa "-out" (key-file name) "2048")
  (openssl-req "-new" "-key" (key-file name) "-subj" dn "-out" (csr-file name))
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

(current-x509-store
 (send (current-x509-store) add
       #:trusted-certs (read-certs (cert-file "ca"))))
