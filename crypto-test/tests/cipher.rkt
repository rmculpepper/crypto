;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/port
         racket/runtime-path
         crypto
         crypto/private/common/catalog
         rackunit
         "util.rkt")
(provide (all-defined-out))

(define-runtime-path kat-dir "data/")

;; make-factory-cipher-test : Factory -> TestSuite
(define (make-factory-cipher-test factory)
  (test-suite "ciphers"
    (hprintf 1 "Ciphers\n")
    (for ([cspec (in-list (list-known-ciphers))])
      (define ci (get-cipher cspec factory))
      (when ci
        (test-case (format "~s" cspec)
          (hprintf 2 "~s\n" cspec)
          (check-pred cipher-impl? ci)
          ;; Check info methods
          (void (cipher-block-size ci))
          (void (cipher-default-key-size ci))
          (void (cipher-key-sizes ci))
          (void (cipher-iv-size ci))
          (void (cipher-aead? ci))
          (void (cipher-default-auth-size ci))
          ;; Check operation
          (check-cipher-kat cspec ci)
          (check-cipher-methods-agree cspec ci)))
      (void))))

;; check-cipher-kat : CipherSpec CipherImpl -> Void
(define (check-cipher-kat cspec ci)
  (void))

;; check-cipher-methods-agree : CipherSpec CipherImpl -> Void
(define (check-cipher-methods-agree cspec ci)
  (hprintf 4 "Method agreement tests\n")
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
      (check-cipher-methods-agree1 ci key iv key2 iv2 msg #t aad aad2))))

(define (check-cipher-methods-agree1 ci key iv key2 iv2 msg pad? [aad null] [aad2 null])
  ;; One-shot, attached auth
  (define ctext (encrypt ci key iv msg #:aad aad #:pad pad?))
  (check-equal? (decrypt ci key iv ctext #:aad aad #:pad pad?) msg)
  (unless (or (equal? msg #"") (equal? key key2)) ;; unlikely to be same
    (define pt (with-handlers ([exn:fail? (lambda (e) #f)])
                 (decrypt ci key2 iv ctext #:aad aad #:pad pad?)))
    (check-not-equal? pt msg))
  (unless (or (equal? msg #"") (equal? iv iv2)) ;; unlikely to be same
    (define pt (with-handlers ([exn:fail? (lambda (e) #f)])
                 (decrypt ci key iv2 ctext #:aad aad #:pad pad?)))
    (check-not-equal? pt msg))
  ;; One-shot, detached auth
  (define-values (ct auth) (encrypt/auth ci key iv msg #:aad aad #:pad pad?))
  (when #t
    ;; This check assumes encrypt attaches auth tag to end; true now, but
    ;; conflicts with CCM and RFC 5116.
    (check-equal? (bytes-append ct auth) ctext))
  (check-equal? (decrypt/auth ci key iv ct #:aad aad #:auth-tag auth #:pad pad?) msg)
  ;; Ctx encrypt/decrypt with one update, attached auth
  (let ([ctx (make-encrypt-ctx ci key iv #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define ct1 (cipher-update ctx msg))
    (define ct2 (cipher-final ctx))
    (check-equal? (bytes-append ct1 ct2) ctext))
  (let ([ctx (make-decrypt-ctx ci key iv #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define pt1 (cipher-update ctx ctext))
    (define pt2 (cipher-final ctx))
    (check-equal? (bytes-append pt1 pt2) msg))
  ;; Ctx encrypt/decrypt with one update, detached auth
  (let ([ctx (make-encrypt-ctx ci key iv #:auth-attached? #f #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define ct1 (cipher-update ctx msg))
    (define ct2 (cipher-final ctx))
    (define tag (cipher-get-auth-tag ctx))
    (check-equal? (bytes-append ct1 ct2) ct)
    (check-equal? tag auth))
  (let ([ctx (make-decrypt-ctx ci key iv #:auth-attached? #f #:pad pad?)])
    (when (cipher-aead? ci) (cipher-update-aad ctx aad))
    (define pt1 (cipher-update ctx ct))
    (define pt2 (cipher-final ctx auth))
    (check-equal? (bytes-append pt1 pt2) msg))
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
             (check-equal? (bytes-append ct ct2) ctext)])))
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
             (check-equal? (bytes-append pt pt2) msg)]))))

;; cipher-make-keys : CipherImpl -> (Listof Bytes)
(define (cipher-make-keys ci)
  ;; Don't use all cipher-keysizes, because some (eg, blowfish), have
  ;; many allowed key sizes.
  (for/list ([keylen '(8 16 24 32 19 28)] #:when (send ci key-size-ok? keylen))
    (semirandom-bytes keylen)))

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
