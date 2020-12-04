#lang racket/base
(require racket/class
         racket/list
         racket/cmdline
         rackunit
         crypto crypto/all
         x509)
(provide (all-defined-out))

;; This test should be run in the OpenSSL source distribution, in the
;; $SRC/test/certs directory.

;; See $SRC/test/recipes/25-test_verify.t for expected behavior.

(crypto-factories libcrypto-factory) ;; all tests enabled pass
;(crypto-factories gcrypt-factory)    ;; all tests enabled pass
;(crypto-factories nettle-factory)    ;; can't handle PSS w/ sha1; others pass

(command-line
 #:args ([ossl-test-cert-dir #f])
 (cond [ossl-test-cert-dir
        (current-directory ossl-test-cert-dir)]
       [else
        (eprintf "OpenSSL test/certs directory not provided. Skipping tests.\n")
        (exit 0)]))

(when #f
(define store
  (send (empty-certificate-store) add
        #:trusted-certs (append*
                         (map pem-file->certificates
                              '("root-cert.pem" "root-ed448-cert.pem")))
        #:untrusted-certs (append*
                           (map pem-file->certificates
                                '("root-nonca.pem" "root-name2.pem" "root-cert2.pem"
                                  "ca-cert.pem" "ca-nonca.pem" "ca-cert2.pem"
                                  "ca-name2.pem" "ca-root2.pem" "ca-expired.pem"
                                  "ca-cert-ec-explicit.pem" "ca-cert-ec-named.pem"
                                  "cca-cert.pem" "sca-cert.pem"
                                  "ncca1-cert.pem" "ncca2-cert.pem" "ncca3-cert.pem")))))

(define (test-ok pem-file)
  (test-case pem-file
    (define ch (send store pem-file->chain pem-file))
    (check-pred certificate-chain? ch)))

(define (test-reject pem-file)
  (test-case pem-file
    (check-exn exn:x509?
               (lambda () (send store pem-file->chain pem-file)))))

;; ++ root-cert
;; + root-nonca
;; + root-cert2
;; + root-name2

;; ? root-cert-md5
;; ? root-cert-768

;; ? croot-cert - w/ clientAuth
;; ? sroot-cert - w/ serverAuth

;; + ca-cert - OK
;; + ca-nonca - not CA
(test-reject "ca-nonbc.pem") ;; invalid cert
;; + ca-cert2 - OK, same name, other key
;; + ca-name2 - OK, same key, other name
;; + ca-root2 - not OK, signed by untrusted root2
;; + ca-expired

;; ? ca-cert-md5
;; ? ca-cert-768i
;; ? ca-cert-768
;; + ca-cert-ec-explicit
;; + ca-cert-ec-named

;; + cca-cert
;; + sca-cert

(test-ok "ee-cert.pem")
(test-reject "ee-expired.pem")
(test-ok "ee-cert2.pem")
(test-ok "ee-name2.pem")
(test-ok "ee-client.pem")
(test-reject "ee-pathlen.pem")

(test-ok "ee-cert-md5.pem") ;; FIXME, security level
;; ? ee-cert-768i
(test-ok "ee-cert-768.pem") ;; FIXME, security level
(test-ok "ee-cert-ec-explicit.pem") ;; ??
(test-ok "ee-cert-ec-named-explicit.pem") ;; ??
(test-ok "ee-cert-ec-named-named.pem") ;; ??

(test-reject "ee-self-signed.pem")

;; Skipping proxy certs

;; + ncca1-cert
;; + ncca2-cert
;; + ncca3-cert

(test-ok "alt1-cert.pem")
(test-ok "goodcn1-cert.pem")
(test-ok "badcn1-cert.pem") ;; ???
(test-ok "alt2-cert.pem")
(test-reject "badalt1-cert.pem") ;; bad DNS SAN; FIXME!
(test-reject "badalt2-cert.pem")
(test-reject "badalt3-cert.pem") ;; FIXME
(test-reject "badalt4-cert.pem") ;; subject email address
(test-reject "badalt5-cert.pem")
(test-reject "badalt6-cert.pem") ;; FIXME: CN-as-DNS
(test-reject "badalt7-cert.pem") ;; FIXME: CN-as-DNS
(test-ok "alt3-cert.pem")
(test-reject "badalt8-cert.pem")
(test-reject "badalt9-cert.pem")
(test-reject "badalt10-cert.pem")

;; ee-pss-sha1-cert
;; ee-pss-sha256-cert
;; ? server-ecdsa-brainpoolP256r1-cert -- BAD, issued by "rootcert" (typo?)
;; ? server-pss-restrict-cert -- BAD, issued by "rootcert" (typo?)

;; ++ root-ed448-cert

(test-ok "server-ed448-cert.pem")

(test-ok "ee-cert-noncrit-unknown-ext.pem")
(test-reject "ee-cert-crit-unknown-ext.pem")
(test-ok "ee-cert-ocsp-nocheck.pem") ;; FIXME
(void))

;; ============================================================
;; Adapted from $SRC/test/recipes/25-test_verify.t

(define (verify cert purpose trusted untrusted)
  (define (pemcerts name) (pem-file->certificates (format "~a.pem" name)))
  (define store (send (empty-certificate-store) add
                      #:trusted-certs (append* (map pemcerts trusted))
                      #:untrusted-certs (append* (map pemcerts untrusted))))
  (define chain (send store pem-file->chain (format "~a.pem" cert)))
  ;; FIXME: check purpose
  chain)

(define (test-v cert purpose trusted untrusted comment #:o [opt #f])
  (test-case (format "~a / ~a" cert comment)
    (define chain (verify cert purpose trusted untrusted))
    (check-pred certificate-chain? chain)
    (case purpose
      [("sslserver") (check-equal? (send chain suitable-for-tls-server? #f) #t)]
      [("Xsslserver") (void)] ;; For certs that don't contain serverAuth EKU
      [("sslclient") (check-equal? (send chain suitable-for-tls-client? #f) #t)])))

(define (test-no cert purpose trusted untrusted comment #:o [opt #f])
  (test-case (format "~a / ~a" cert comment)
    (check-exn exn:x509?
               (lambda () (verify cert purpose trusted untrusted)))))

(define (test-uns cert purpose trusted untrusted comment #:o [opt #f])
  (test-case (format "~a / ~a" cert comment)
    (define chain (verify cert purpose trusted untrusted))
    (check-pred certificate-chain? chain)
    (case purpose
      [("sslserver") (check-equal? (send chain suitable-for-tls-server? #f) #f)]
      [("sslclient") (check-equal? (send chain suitable-for-tls-client? #f) #f)])))

(define-syntax-rule (XFAIL form ...) (when #f form ... (void)))
(define-syntax-rule (SKIP form ...) (when #f form ... (void)))

;; Canonical success
(test-v "ee-cert" "sslserver" '["root-cert"] '["ca-cert"]
        "accept compat trust")

;; Root CA variants
(test-no "ee-cert" "sslserver" '[root-nonca] '[ca-cert]
         "fail trusted non-ca root")
(SKIP ;; uses TRUSTED CERTIFICATE
 (test-no "ee-cert" "sslserver" '[nroot+serverAuth] '[ca-cert]
          "fail server trust non-ca root")
 (test-no "ee-cert" "sslserver" '[nroot+anyEKU] '[ca-cert]
          "fail wildcard trust non-ca root"))
(test-no "ee-cert" "sslserver" '[root-cert2] '[ca-cert]
         "fail wrong root key")
(test-no "ee-cert" "sslserver" '[root-name2] '[ca-cert]
         "fail wrong root DN")

;; Critical extensions

(test-v "ee-cert-noncrit-unknown-ext" "sslserver" '[root-cert] '[ca-cert]
        "accept non-critical unknown extension")
(test-no "ee-cert-crit-unknown-ext" "sslserver" '[root-cert] '[ca-cert]
         "reject critical unknown extension")
(test-v "ee-cert-ocsp-nocheck" "sslserver" '[root-cert] '[ca-cert]
        "accept critical OCSP No Check")

;; Explicit trust/purpose combinations

(test-v "ee-cert" "sslserver" '[sroot-cert] '[ca-cert]
        "accept server purpose")
(test-uns "ee-cert" "sslserver" '[croot-cert] '[ca-cert]
          "fail client purpose")
(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[root+serverAuth] '[ca-cert]
         "accept server trust")
 (test-v "ee-cert" "sslserver" '[sroot+serverAuth] '[ca-cert]
         "accept server trust with server purpose")
 (test-v "ee-cert" "sslserver" '[croot+serverAuth] '[ca-cert]
         "accept server trust with client purpose")
 ;; Wildcard trust
 (test-v "ee-cert" "sslserver" '[root+anyEKU] '[ca-cert]
         "accept wildcard trust")
 (test-v "ee-cert" "sslserver" '[sroot+anyEKU] '[ca-cert]
         "accept wildcard trust with server purpose")
 (test-v "ee-cert" "sslserver" '[croot+anyEKU] '[ca-cert]
         "accept wildcard trust with client purpose")
 ;; Inapplicable mistrust
 (test-v "ee-cert" "sslserver" '[root-clientAuth] '[ca-cert]
         "accept client mistrust")
 (test-v "ee-cert" "sslserver" '[sroot-clientAuth] '[ca-cert]
         "accept client mistrust with server purpose")
 (test-no "ee-cert" "sslserver" '[croot-clientAuth] '[ca-cert]
          "fail client mistrust with client purpose")
 ;; Inapplicable trust
 (test-no "ee-cert" "sslserver" '[root+clientAuth] '[ca-cert]
          "fail client trust")
 (test-no "ee-cert" "sslserver" '[sroot+clientAuth] '[ca-cert]
          "fail client trust with server purpose")
 (test-no "ee-cert" "sslserver" '[croot+clientAuth] '[ca-cert]
          "fail client trust with client purpose")
 ;; Server mistrust
 (test-no "ee-cert" "sslserver" '[root-serverAuth] '[ca-cert]
          "fail rejected EKU")
 (test-no "ee-cert" "sslserver" '[sroot-serverAuth] '[ca-cert]
          "fail server mistrust with server purpose")
 (test-no "ee-cert" "sslserver" '[croot-serverAuth] '[ca-cert]
          "fail server mistrust with client purpose")
 ;; Wildcard mistrust
 (test-no "ee-cert" "sslserver" '[root-anyEKU] '[ca-cert]
          "fail wildcard mistrust")
 (test-no "ee-cert" "sslserver" '[sroot-anyEKU] '[ca-cert]
          "fail wildcard mistrust with server purpose")
 (test-no "ee-cert" "sslserver" '[croot-anyEKU] '[ca-cert]
          "fail wildcard mistrust with client purpose"))

;; Check that trusted-first is on by setting up paths to different roots
;; depending on whether the intermediate is the trusted or untrusted one.

(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[root-serverAuth root-cert2 ca-root2] '[ca-cert]
         "accept trusted-first path")
 (test-v "ee-cert" "sslserver" '[root-cert root2+serverAuth ca-root2] '[ca-cert]
         "accept trusted-first path with server trust")
 (test-no "ee-cert" "sslserver" '[root-cert root2-serverAuth ca-root2] '[ca-cert]
          "fail trusted-first path with server mistrust")
 (test-no "ee-cert" "sslserver" '[root-cert root2+clientAuth ca-root2] '[ca-cert]
          "fail trusted-first path with client trust"))

;; CA variants

(test-no "ee-cert" "sslserver" '[root-cert] '[ca-nonca]
         "fail non-CA untrusted intermediate")
(test-no "ee-cert" "sslserver" '[root-cert] '[ca-nonbc]
         "fail non-CA untrusted intermediate")
(test-no "ee-cert" "sslserver" '[root-cert ca-nonca] '[]
         "fail non-CA trust-store intermediate")
(test-no "ee-cert" "sslserver" '[root-cert ca-nonbc] '[]
         "fail non-CA trust-store intermediate")
(SKIP ;; trusted certs
 (test-no "ee-cert" "sslserver" '[root-cert nca+serverAuth] '[]
          "fail non-CA server trust intermediate")
 (test-no "ee-cert" "sslserver" '[root-cert nca+anyEKU] '[]
          "fail non-CA wildcard trust intermediate"))
(test-no "ee-cert" "sslserver" '[root-cert] '[ca-cert2]
         "fail wrong intermediate CA key")
(test-no "ee-cert" "sslserver" '[root-cert] '[ca-name2]
         "fail wrong intermediate CA DN")
(test-no "ee-cert" "sslserver" '[root-cert] '[ca-root2]
         "fail wrong intermediate CA issuer")

(test-no "ee-cert" "sslserver" '[] '[ca-cert] #:o "-partial_chain"
         "fail untrusted partial chain")
(test-v "ee-cert" "sslserver" '[ca-cert] '[] #:o "-partial_chain"
        "accept trusted partial chain")
(test-v "ee-cert" "sslserver" '[sca-cert] '[] #:o "-partial_chain"
        "accept partial chain with server purpose");
(test-uns "ee-cert" "sslserver" '[cca-cert] '[] #:o "-partial_chain"
          "fail partial chain with client purpose")
(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[ca+serverAuth] '[] #:o "-partial_chain"
         "accept server trust partial chain")
 (test-v "ee-cert" "sslserver" '[cca+serverAuth] '[] #:o "-partial_chain"
         "accept server trust client purpose partial chain")
 (test-v "ee-cert" "sslserver" '[ca-clientAuth] '[] #:o "-partial_chain"
         "accept client mistrust partial chain")
 (test-v "ee-cert" "sslserver" '[ca+anyEKU] '[] #:o "-partial_chain"
         "accept wildcard trust partial chain")
 (test-no "ee-cert" "sslserver" '[] '[ca+serverAuth] #:o "-partial_chain"
          "fail untrusted partial issuer with ignored server trust")
 (test-no "ee-cert" "sslserver" '[ca-serverAuth] '[] #:o "-partial_chain"
          "fail server mistrust partial chain")
 (test-no "ee-cert" "sslserver" '[ca+clientAuth] '[] #:o "-partial_chain"
          "fail client trust partial chain")
 (test-no "ee-cert" "sslserver" '[ca-anyEKU] '[] #:o "-partial_chain"
          "fail wildcard mistrust partial chain"))

;; We now test auxiliary trust even for intermediate trusted certs without
;; -partial_chain.  Note that "-trusted_first" is now always on and cannot
;; be disabled.

(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[root-cert ca+serverAuth] '[ca-cert]
         "accept server trust")
 (test-v "ee-cert" "sslserver" '[root-cert ca+anyEKU] '[ca-cert]
         "accept wildcard trust"))
(test-v "ee-cert" "sslserver" '[root-cert sca-cert] '[ca-cert]
        "accept server purpose")
(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[root-cert sca+serverAuth] '[ca-cert]
         "accept server trust and purpose")
 (test-v "ee-cert" "sslserver" '[root-cert sca+anyEKU] '[ca-cert]
         "accept wildcard trust and server purpose")
 (test-v "ee-cert" "sslserver" '[root-cert sca-clientAuth] '[ca-cert]
         "accept client mistrust and server purpose")
 (test-v "ee-cert" "sslserver" '[root-cert cca+serverAuth] '[ca-cert]
         "accept server trust and client purpose")
 (test-v "ee-cert" "sslserver" '[root-cert cca+anyEKU] '[ca-cert]
         "accept wildcard trust and client purpose"))
(test-uns "ee-cert" "sslserver" '[root-cert cca-cert] '[ca-cert]
          "fail client purpose")
(SKIP ;; trusted certs
 (test-no "ee-cert" "sslserver" '[root-cert ca-anyEKU] '[ca-cert]
          "fail wildcard mistrust")
 (test-no "ee-cert" "sslserver" '[root-cert ca-serverAuth] '[ca-cert]
          "fail server mistrust")
 (test-no "ee-cert" "sslserver" '[root-cert ca+clientAuth] '[ca-cert]
          "fail client trust")
 (test-no "ee-cert" "sslserver" '[root-cert sca+clientAuth] '[ca-cert]
          "fail client trust and server purpose")
 (test-no "ee-cert" "sslserver" '[root-cert cca+clientAuth] '[ca-cert]
          "fail client trust and client purpose")
 (test-no "ee-cert" "sslserver" '[root-cert cca-serverAuth] '[ca-cert]
          "fail server mistrust and client purpose")
 (test-no "ee-cert" "sslserver" '[root-cert cca-clientAuth] '[ca-cert]
          "fail client mistrust and client purpose")
 (test-no "ee-cert" "sslserver" '[root-cert sca-serverAuth] '[ca-cert]
          "fail server mistrust and server purpose")
 (test-no "ee-cert" "sslserver" '[root-cert sca-anyEKU] '[ca-cert]
          "fail wildcard mistrust and server purpose")
 (test-no "ee-cert" "sslserver" '[root-cert cca-anyEKU] '[ca-cert]
          "fail wildcard mistrust and client purpose"))

;; EE variants

(test-v "ee-client" "sslclient" '[root-cert] '[ca-cert]
        "accept client chain")
(test-uns "ee-client" "sslserver" '[root-cert] '[ca-cert]
          "fail server leaf purpose")
(test-uns "ee-cert" "sslclient" '[root-cert] '[ca-cert]
          "fail client leaf purpose")
(test-no "ee-cert2" "sslserver" '[root-cert] '[ca-cert]
         "fail wrong intermediate CA key")
(test-no "ee-name2" "sslserver" '[root-cert] '[ca-cert]
         "fail wrong intermediate CA DN")
(test-no "ee-expired" "sslserver" '[root-cert] '[ca-cert]
         "fail expired leaf")
(test-v "ee-cert" "sslserver" '[ee-cert] '[] #:o "-partial_chain"
        "accept last-resort direct leaf match")
(test-v "ee-client" "sslclient" '[ee-client] '[] #:o "-partial_chain"
        "accept last-resort direct leaf match")
(test-no "ee-cert" "sslserver" '[ee-client] '[] #:o "-partial_chain"
         "fail last-resort direct leaf non-match")
(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '[ee+serverAuth] '[] #:o "-partial_chain"
         "accept direct match with server trust")
 (test-no "ee-cert" "sslserver" '[ee-serverAuth] '[] #:o "-partial_chain"
          "fail direct match with server mistrust")
 (test-v "ee-client" "sslclient" '[ee+clientAuth] '[] #:o "-partial_chain"
         "accept direct match with client trust")
 (test-no "ee-client" "sslclient" '[ee-clientAuth] '[] #:o "-partial_chain"
          "reject direct match with client mistrust"))
(XFAIL ;; rejected
 (test-v "ee-pathlen" "sslserver" '[root-cert] '[ca-cert]
         "accept non-ca with pathlen:0 by default"))
(test-no "ee-pathlen" "sslserver" '[root-cert] '[ca-cert] #:o "-x509_strict"
         "reject non-ca with pathlen:0 with strict flag")

;; Proxy certificates

(SKIP ;; proxy certs not implemented
 (test-no "pc1-cert" "sslclient" '[root-cert] '[ee-client ca-cert]
          "fail to accept proxy cert without -allow_proxy_certs")
 (test-v "pc1-cert" "sslclient" '[root-cert] '[ee-client ca-cert] #:o "-allow_proxy_certs"
         "accept proxy cert 1")
 (test-v "pc2-cert" "sslclient" '[root-cert] '[pc1-cert ee-client ca-cert] #:o "-allow_proxy_certs"
         "accept proxy cert 2")
 (test-no "bad-pc3-cert" "sslclient" '[root-cert] '[pc1-cert ee-client ca-cert]
          #:o "-allow_proxy_certs"
          "fail proxy cert with incorrect subject")
 (test-no "bad-pc4-cert" "sslclient" '[root-cert] '[pc1-cert ee-client ca-cert]
          #:o "-allow_proxy_certs"
          "fail proxy cert with incorrect pathlen")
 (test-v "pc5-cert" "sslclient" '[root-cert] '[pc1-cert ee-client ca-cert]
         #:o "-allow_proxy_certs"
         "accept proxy cert missing proxy policy")
 (test-no "pc6-cert" "sslclient" '[root-cert] '[pc1-cert ee-client ca-cert]
          #:o "-allow_proxy_certs"
          "failed proxy cert where last CN was added as a multivalue RDN component"))

;; Security level tests
;; Security levels not implemented, so disable the reject tests.

;; Slightly reordered:
(begin
 (test-v "ee-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "2")
         "accept RSA 2048 chain at auth level 2")
 (test-v "ee-cert" "sslserver" '["root-cert-768"] '["ca-cert-768i"] #:o '("-auth_level" "0")
         "accept RSA 768 root at auth level 0")
 (test-v "ee-cert-768i" "sslserver" '["root-cert"] '["ca-cert-768"] #:o '("-auth_level" "0")
         "accept RSA 768 intermediate at auth level 0")
 (test-v "ee-cert-768" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "0")
         "accept RSA 768 leaf at auth level 0"))
(SKIP ;; security levels not implemented
 (test-no "ee-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "3")
          "reject RSA 2048 root at auth level 3")
 (test-no "ee-cert" "sslserver" '["root-cert-768"] '["ca-cert-768i"]
          "reject RSA 768 root at auth level 1")
 (test-no "ee-cert-768i" "sslserver" '["root-cert"] '["ca-cert-768"]
          "reject RSA 768 intermediate at auth level 1")
 (test-no "ee-cert-768" "sslserver" '["root-cert"] '["ca-cert"]
          "reject RSA 768 leaf at auth level 1"))

(begin
 (test-v "ee-cert" "sslserver" '["root-cert-md5"] '["ca-cert"] #:o '("-auth_level" "2")
         "accept md5 self-signed TA at auth level 2")
 (test-v "ee-cert" "sslserver" '["root-cert"] '["ca-cert-md5"] #:o '("-auth_level" "0")
         "accept md5 intermediate at auth level 0")
 (test-v "ee-cert-md5" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "0")
         "accept md5 leaf at auth level 0"))
(SKIP ;; security levels not implemented
 (test-no "ee-cert" "sslserver" '["root-cert"] '["ca-cert-md5"]
          "reject md5 intermediate at auth level 1")
 (test-no "ee-cert-md5" "sslserver" '["root-cert"] '["ca-cert"]
          "reject md5 leaf at auth level 1"))
(SKIP ;; trusted certs
 (test-v "ee-cert" "sslserver" '["ca-cert-md5-any"] '[] #:o '("-auth_level" "2")
         "accept md5 intermediate TA at auth level 2"))

;; Explicit vs named curve tests

(XFAIL ;; ??? some rule about explicit curves ???
 (test-no "ee-cert-ec-explicit" "sslserver" '["root-cert"] '["ca-cert-ec-named"]
          "reject explicit curve leaf with named curve intermediate")
 (test-no "ee-cert-ec-named-explicit" "sslserver" '["root-cert"] '["ca-cert-ec-explicit"]
          "reject named curve leaf with explicit curve intermediate"))
(test-v "ee-cert-ec-named-named" "sslserver" '["root-cert"] '["ca-cert-ec-named"]
        "accept named curve leaf with named curve intermediate")

;; Depth tests, note the depth limit bounds the number of CA certificates
;; between the trust-anchor and the leaf, so, for example, with a root->ca->leaf
;; chain, depth = 1 is sufficient, but depth == 0 is not.

(SKIP ;; verify-depth not supported
 (test-v "ee-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-verify_depth" "2")
         "accept chain with verify_depth 2")
 (test-v "ee-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-verify_depth" "1")
         "accept chain with verify_depth 1")
 (test-no "ee-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-verify_depth" "0")
          "accept chain with verify_depth 0")
 (test-v "ee-cert" "sslserver" '["ca-cert-md5-any"] '[] #:o '("-verify_depth" "0")
         "accept md5 intermediate TA with verify_depth 0"))

;; Name Constraints tests

;; The NC test certs don't assert serverAuth EKU, so disable
;; suitability check by changing purpose to "Xsslserver".

(test-v "alt1-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
        "Name Constraints everything permitted")

(test-v "alt2-cert" "Xsslserver" '["root-cert"] '["ncca2-cert"]
        "Name Constraints nothing excluded")

(test-v "alt3-cert" "Xsslserver" '["root-cert"] '["ncca1-cert" "ncca3-cert"]
        "Name Constraints nested test all permitted")

(test-v "goodcn1-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
        "Name Constraints CNs permitted")

(XFAIL ;; DNS NC not applied to CN
 (test-no "badcn1-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
          "Name Constraints CNs not permitted"))

(test-no "badalt1-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
         "Name Constraints hostname not permitted")

(test-no "badalt2-cert" "Xsslserver" '["root-cert"] '["ncca2-cert"]
         "Name Constraints hostname excluded")

(test-no "badalt3-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
         "Name Constraints email address not permitted")

(test-no "badalt4-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
         "Name Constraints subject email address not permitted")

(test-no "badalt5-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
         "Name Constraints IP address not permitted")

(XFAIL ;; DNS NC not applied to CN
 (test-no "badalt6-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
          "Name Constraints CN hostname not permitted")
 (test-no "badalt7-cert" "Xsslserver" '["root-cert"] '["ncca1-cert"]
          "Name Constraints CN BMPSTRING hostname not permitted"))

(test-no "badalt8-cert" "Xsslserver" '["root-cert"] '["ncca1-cert" "ncca3-cert"]
         "Name constraints nested DNS name not permitted 1")

(test-no "badalt9-cert" "Xsslserver" '["root-cert"] '["ncca1-cert" "ncca3-cert"]
         "Name constraints nested DNS name not permitted 2")

(test-no "badalt10-cert" "Xsslserver" '["root-cert"] '["ncca1-cert" "ncca3-cert"]
         "Name constraints nested DNS name excluded")

;; ---

(test-v "ee-pss-sha1-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "0")
        "Accept PSS signature using SHA1 at auth level 0")

(test-v "ee-pss-sha256-cert" "sslserver" '["root-cert"] '["ca-cert"]
        "CA with PSS signature using SHA256")

(SKIP ;; security levels not implemented
 (test-no "ee-pss-sha1-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "1")
          "Reject PSS signature using SHA1 and auth level 1"))

(test-v "ee-pss-sha256-cert" "sslserver" '["root-cert"] '["ca-cert"] #:o '("-auth_level" "2")
        "PSS signature using SHA256 and auth level 2")

(XFAIL ;; no limit implemented, not sure what these should do...
 (test-no "many-names1" "sslserver" '["many-constraints"] '["many-constraints"]
          "Too many names and constraints to check (1)")
 (test-no "many-names2" "sslserver" '["many-constraints"] '["many-constraints"]
          "Too many names and constraints to check (2)")
 (test-no "many-names3" "sslserver" '["many-constraints"] '["many-constraints"]
          "Too many names and constraints to check (3)"))

(test-v "some-names1" "sslserver" '["many-constraints"] '["many-constraints"]
        "Not too many names and constraints to check (1)")
(test-v "some-names2" "sslserver" '["many-constraints"] '["many-constraints"]
        "Not too many names and constraints to check (2)")
(test-v "some-names2" "sslserver" '["many-constraints"] '["many-constraints"]
        "Not too many names and constraints to check (3)")

(SKIP ;; alt rsa oid not supported
 (test-v "root-cert-rsa2" "sslserver" '["root-cert-rsa2"] '[] #:o "-check_ss_sig"
         "Public Key Algorithm rsa instead of rsaEncryption"))

(test-v "ee-self-signed" "Xsslserver" '["ee-self-signed"] '[]
        "accept trusted self-signed EE cert excluding key usage keyCertSign")

;; ED25519 certificate from draft-ietf-curdle-pkix-04

(XFAIL ;; these certs are not valid DER: encode CA:false (default value)

 (test-v "ee-ed25519" "sslserver" '["root-ed25519"] '[]
         "accept X25519 EE cert issued by trusted Ed25519 self-signed CA cert")

 (test-no "ee-ed25519" "sslserver" '["root-ed25519"] '[] #:o "-x509_strict"
          "reject X25519 EE cert in strict mode since AKID is missing")

 (test-no "root-ed25519" "sslserver" '["ee-ed25519"] '[]
          "fail Ed25519 CA and EE certs swapped")

 (test-v "root-ed25519" "sslserver" '["root-ed25519"] '[]
         "accept trusted Ed25519 self-signed CA cert")

 (test-no "ee-ed25519" "sslserver" '["ee-ed25519"] '[]
          "fail trusted Ed25519-signed self-issued X25519 cert")

 (test-v "ee-ed25519" "sslserver" '["ee-ed25519"] '[] #:o "-partial_chain"
         "accept last-resort direct leaf match Ed25519-signed self-issued cert"))
