;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/port
         racket/runtime-path
         crypto
         crypto/private/common/catalog
         checkers
         "util.rkt")
(provide test-factory-ciphers
         xtest-ciphers)

(define-runtime-path kat-dir "data/")

;; test-factory-ciphers : Factory -> Void
(define (test-factory-ciphers factory)
  (test #:name "ciphers"
    (for ([cspec (in-list (list-known-ciphers))])
      (define ci (get-cipher cspec factory))
      (when ci
        (test #:name (format "~s" cspec)
          (check ci #:with cipher-impl?)
          ;; Check info methods
          (check (cipher-block-size ci) #:no-error)
          (check (cipher-default-key-size ci) #:no-error)
          (check (cipher-key-sizes ci) #:no-error)
          (check (cipher-iv-size ci) #:no-error)
          (check (cipher-aead? ci) #:no-error)
          (check (cipher-default-auth-size ci) #:no-error)
          ;; Check operation
          (test-cipher-kat cspec ci)
          (test-cipher-methods-agree cspec ci)))
      (void))))

;; test-cipher-kat : CipherSpec CipherImpl -> Void
(define (test-cipher-kat cspec ci)
  (match cspec
    ['(aes gcm)
     (test #:name "encrypt KAT"
       (call-with-input-file (build-path kat-dir "cipher-aes-gcm-encrypt.rktd")
         (lambda (kat-in)
           (for ([datum (in-port read kat-in)])
             (match datum
               [`((Count ,c) (Key ,(app hex->bytes key)) (IV ,(app hex->bytes iv))
                             (PT ,(app hex->bytes pt)) (AAD ,(app hex->bytes aad))
                             (CT ,(app hex->bytes ct)) (Tag ,(app hex->bytes tag)))
                (when (send ci key-size-ok? (bytes-length key))
                  (check (encrypt/auth ci key iv pt #:aad aad)
                         #:is (values ct tag)))])))))
     (test #:name "decrypt KAT"
       (call-with-input-file (build-path kat-dir "cipher-aes-gcm-decrypt.rktd")
         (lambda (kat-in)
           (for ([datum (in-port read kat-in)])
             (match datum
               [`((Count ,c) (Key ,(app hex->bytes key)) (IV ,(app hex->bytes iv))
                             (CT ,(app hex->bytes ct)) (AAD ,(app hex->bytes aad))
                             (Tag ,(app hex->bytes tag)) ,result)
                (when (send ci key-size-ok? (bytes-length key))
                  (match result
                    [`(PT ,(app hex->bytes pt))
                     (check (decrypt/auth ci key iv ct #:aad aad #:auth-tag tag)
                            #:is pt)]
                    ['FAIL
                     (check (decrypt/auth ci key iv ct #:aad aad #:auth-tag tag)
                            #:error #rx"authenticated decryption failed")]))])))))]
    [_ (void)]))

;; test-cipher-methods-agree : CipherSpec CipherImpl -> Void
(define (test-cipher-methods-agree cspec ci)
  (test #:name "agree"
    (for ([key (in-list (cipher-make-keys ci))]
          [key2 (in-list (cipher-make-keys ci))]
          #:when #t
          [msg (in-list messages)])
      (define nopad-ok? (zero? (remainder (bytes-length msg) (cipher-block-size ci))))
      (define iv (generate-cipher-iv ci))
      (define iv2 (generate-cipher-iv ci))
      (check-cipher-methods-agree1 ci key iv key2 iv2 msg #t)
      (when nopad-ok? (check-cipher-methods-agree1 ci key iv key2 iv2 msg #f))
      (when (cipher-aead? ci)
        (define aad (semirandom-bytes 20))
        (define aad2 (semirandom-bytes 20))
        (check-cipher-methods-agree1 ci key iv key2 iv2 msg #t aad aad2)))))

(define (check-cipher-methods-agree1 ci key iv key2 iv2 msg pad? [aad null] [aad2 null])
  ;; One-shot, attached auth
  (define ctext (encrypt ci key iv msg #:aad aad #:pad pad?))
  (check (decrypt ci key iv ctext #:aad aad #:pad pad?) #:is msg)
  (unless (or (equal? msg #"") (equal? key key2)) ;; unlikely to be same
    (check (with-handlers ([exn:fail? (lambda (e) #f)])
             (decrypt ci key2 iv ctext #:aad aad #:pad pad?))
           #:is-not msg))
  (unless (or (equal? msg #"") (equal? iv iv2)) ;; unlikely to be same
    (check (with-handlers ([exn:fail? (lambda (e) #f)])
             (decrypt ci key iv2 ctext #:aad aad #:pad pad?))
           #:is-not msg))
  ;; One-shot, detached auth
  (define-values (ct auth) (encrypt/auth ci key iv msg #:aad aad #:pad pad?))
  (when #t
    ;; This check assumes encrypt attaches auth tag to end; true now, but
    ;; conflicts with CCM and RFC 5116.
    (check (bytes-append ct auth) #:is ctext))
  (check (decrypt/auth ci key iv ct #:aad aad #:auth-tag auth #:pad pad?) #:is msg)
  ;; Ctx encrypt/decrypt with one update, attached auth
  (let ([ctx (make-encrypt-ctx ci key iv #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define ct1 (cipher-update ctx msg))
    (define ct2 (cipher-final ctx))
    (check (bytes-append ct1 ct2) #:is ctext))
  (let ([ctx (make-decrypt-ctx ci key iv #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define pt1 (cipher-update ctx ctext))
    (define pt2 (cipher-final ctx))
    (check (bytes-append pt1 pt2) #:is msg))
  ;; Ctx encrypt/decrypt with one update, detached auth
  (let ([ctx (make-encrypt-ctx ci key iv #:auth-attached? #f #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define ct1 (cipher-update ctx msg))
    (define ct2 (cipher-final ctx))
    (define tag (cipher-get-auth-tag ctx))
    (check (bytes-append ct1 ct2) #:is ct)
    (check tag #:is auth))
  (let ([ctx (make-decrypt-ctx ci key iv #:auth-attached? #f #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define pt1 (cipher-update ctx ct))
    (define pt2 (cipher-final ctx auth))
    (check (bytes-append pt1 pt2) #:is msg))
  ;; Ctx encrypt/decrypt with random-sized updates, attached auth
  (let ([ctx (make-encrypt-ctx ci key iv #:pad pad?)])
    (define msglen (bytes-length msg))
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (let loop ([start 0] [ct #""])
      (cond [(< start msglen)
             (define end (+ start 1 (random (- msglen start))))
             (define ct2 (cipher-update ctx (subbytes msg start end)))
             (loop end (bytes-append ct ct2))]
            [else
             (define ct2 (cipher-final ctx))
             (check (bytes-append ct ct2) #:is ctext)])))
  (let ([ctx (make-decrypt-ctx ci key iv #:pad pad?)])
    (define ctlen (bytes-length ctext))
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (let loop ([start 0] [pt #""])
      (cond [(< start ctlen)
             (define end (+ start 1 (random (- ctlen start))))
             (define pt2 (cipher-update ctx (subbytes ctext start end)))
             (loop end (bytes-append pt pt2))]
            [else
             (define pt2 (cipher-final ctx))
             (check (bytes-append pt pt2) #:is msg)]))))

;; cipher-make-keys : CipherImpl -> (Listof Bytes)
(define (cipher-make-keys ci)
  ;; Don't use all cipher-keysizes, because some (eg, blowfish), have
  ;; many allowed key sizes.
  (for/list ([keylen '(8 16 24 32 19 28)] #:when (send ci key-size-ok? keylen))
    (semirandom-bytes keylen)))

;; ============================================================

;; xtest-ciphers : (Listof Factory) -> Void
(define (xtest-ciphers factories)
  (test #:name "ciphers cross"
    (for ([cspec (in-list (list-known-ciphers))])
      (define (get-ci factory) (get-cipher cspec factory))
      (define cis (filter values (map get-ci factories)))
      (when (> (length cis) 1)
        (test #:name (format "~s (~s)" cspec (length cis))
          (define ci0 (car cis))
          (for ([keylen (in-list '(16 24 32))]
                #:when (send ci0 key-size-ok? keylen))
            (define key (semirandom-bytes keylen))
            (define iv (generate-cipher-iv ci0))
            (for ([msg (in-list messages)])
              (define ct (encrypt ci0 key iv msg))
              (for ([ci (in-list cis)]
                    #:when (send ci key-size-ok? keylen))
                (check (encrypt ci key iv msg) #:is ct)
                (check (decrypt ci key iv ct) #:is msg)))))))))

;; ============================================================

;; messages : (Listof Bytes)
(define messages
  (list #""
        #"abc"
        (make-bytes 8 #x00)
        (semirandom-bytes 16)
        (semirandom-bytes 46)
        (semirandom-bytes 47)
        (semirandom-bytes 48)
        (semirandom-bytes 49)
        (semirandom-bytes 1000)))

;; ============================================================

(define (run-cipher-tests factories)
  (for ([factory (in-list factories)])
    (test #:name (send factory get-display-name)
      (test-factory-ciphers factory)))
  (xtest-ciphers factories))

(module+ test
  (require crypto/all)
  (run-cipher-tests all-factories))

(module+ main
  (require crypto/all)
  (run-tests (lambda () (run-cipher-tests all-factories))
             #:progress? #t))
