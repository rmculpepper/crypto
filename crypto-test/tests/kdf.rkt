;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         racket/runtime-path
         checkers
         crypto
         crypto/private/common/catalog
         (prefix-in rkt: crypto/private/rkt/pbkdf2)
         "util.rkt")
(provide test-factory-kdfs
         test-kdfs-agree)

(define-runtime-path kat-dir "data/")

(define (test-factory-kdfs factory)
  (test #:name "kdf"
    (test-kdf-kat factory)
    (for ([name (list-known-kdfs)])
      (define impl (send factory get-kdf name))
      (when impl
        (test #:name (format "~s" name)
          (test #:name "as kdf"
            (define config (get-config name))
            (let ([salt (and (send impl salt-allowed?) salt)])
              (check (kdf impl key salt config) #:with bytes?)
              (match name
                [(list 'pbkdf2 'hmac di)
                 (define dimpl (send factory get-digest di))
                 (when dimpl
                   (check (kdf impl key salt '((iterations 2000) (key-size 89)))
                          #:is (rkt:pbkdf2-hmac dimpl key salt 2000 89)))]
                [_ (void)])))
          (define pwconfig (get-pwhash-config name))
          (when pwconfig
            (test #:name "as pwhash"
              (define cred (pwhash impl key pwconfig))
              (check (pwhash-verify impl key cred) #:is #t)
              (check (pwhash-verify impl badkey cred) #:is #f)
              (check (pwhash-verify impl key bad-pwh)
                     #:error #rx"algorithm does not match")
              (check (pwhash-verify impl key unsupported-pwh)
                     #:error #rx"algorithm does not match"))))))))

;; ----------------------------------------

(define (test-kdf-kat factory)
  (define (kat-for-each file handle-test-datum)
    (call-with-input-file (build-path kat-dir file)
      (lambda (kat-in)
        (for ([datum (in-port read kat-in)])
          (handle-datum datum handle-test-datum)))))
  (define (handle-datum datum handle-test-datum)
    (match datum
      [(list* 'kdf kdfspec test-data)
       (define kdfi (get-kdf kdfspec factory))
       (when kdfi
         (test #:name (format "~s" kdfspec)
           (for ([test-datum (in-list test-data)])
             (handle-test-datum kdfi test-datum))))]))
  (test #:name "kat"
    (kat-for-each "kdf-misc.rktd" check-misc-kat)
    (kat-for-each "kdf-sp800-108-counter.rktd" check-sp800-kat)
    (kat-for-each "kdf-sp800-108-feedback.rktd" check-sp800-kat)
    (kat-for-each "kdf-sp800-108-double-pipeline.rktd" check-sp800-kat)
    #;(test-argon-kat factory)))

(define (check-misc-kat kdfi test-datum)
  (define (do-check z L info expected)
    (let ([L (or L (bytes-length expected))])
      (kdf kdfi z salt `((key-size ,L) (info ,info)))))
  (define (get key [f values])
    (cond [(memq key test-datum) => (lambda (l) (f (cadr l)))] [else #f]))
  (define z    (get '#:z hex->bytes))
  (define salt (get '#:salt hex->bytes))
  (define info (get '#:info hex->bytes))
  (define expected (get '#:= hex->bytes))
  (define L (or (get '#:L) (bytes-length expected)))
  (check (kdf kdfi z salt `((key-size ,L) ,@(if info `((info ,info)) null)))
         #:is expected))

(define (check-sp800-kat kdfi test-datum)
  (match test-datum
    [`((KI ,(app hex->bytes in))
       (FixedInputData ,(app hex->bytes info))
       (KO ,(app hex->bytes out)))
     (check (kdf kdfi in #f `((key-size ,(bytes-length out)) (info ,info))) #:is out)]
    [`((KI ,(app hex->bytes in))
       (IV ,(app hex->bytes iv))
       (FixedInputData ,(app hex->bytes info))
       (KO ,(app hex->bytes out)))
     (check (kdf kdfi in iv `((key-size ,(bytes-length out)) (info ,info))) #:is out)]
    #;[_ (void)]))

#;
;; Most impls do not support secret, AD inputs
(define (test-argon-kat factory)
  ;; Argon2 (https://datatracker.ietf.org/doc/rfc9106/, Section 5)
  (define argon2d (get-kdf 'argon2d factory))
  (define argon2i (get-kdf 'argon2i factory))
  (define argon2id (get-kdf 'argon2id factory))
  (define pass (make-bytes 32 #x01))
  (define salt (make-bytes 16 #x02))
  (define secret (make-bytes 8 #x03))
  (define ad (make-bytes 12 #x04))
  (define conf `((t 3) (m 32) (p 4) (secret ,secret) (ad ,ad) (key-size 32)))
  (when argon2d
    (test #:name "argon2d"
      (check (kdf argon2d pass salt conf)
             #:is (hex->bytes
                   "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"))))
  (when argon2i
    (test #:name "argon2i"
      (check (kdf argon2i pass salt conf)
             #:is (hex->bytes
                   "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8"))))
  (when argon2id
    (test #:name "argon2id"
      (check (kdf argon2id pass salt conf)
             #:is (hex->bytes
                   "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"))))
  (void))

;; ----------------------------------------

(define (test-kdfs-agree factories)
  (test #:name "kdf cross-tests"
    (for ([name (list-known-kdfs)])
      (define config (get-config name))
      (define pwconfig (get-pwhash-config name))
      (define impls
        (filter values
                (for/list ([factory factories])
                  (send factory get-kdf name))))
      (when (= (length impls) 1)
        (void))
      (when (> (length impls) 1)
        (test #:name (format "~a" name)
          (define impl0 (car impls))
          (define salt* (and (send impl0 salt-allowed?) salt))
          (define r0 (kdf impl0 key salt* config))
          (define cred0 (and pwconfig (pwhash impl0 key pwconfig)))
          (for ([impl (cdr impls)])
            (check (kdf impl key salt* config) #:is r0)
            (when pwconfig
              (check (pwhash-verify impl key cred0) #:is #t)
              (check (pwhash-verify impl badkey cred0) #:is #f)
              (define cred1 (pwhash impl key pwconfig))
              (check (pwhash-verify impl0 key cred1) #:is #t)
              (check (pwhash-verify impl0 badkey cred1) #:is #f))))))))

(define (get-config name)
  (match name
    [(list 'pbkdf2 'hmac _)
     `((iterations #e1e4) (key-size 48))]
    ['scrypt
     `((N ,(expt 2 16)) (p 1) (r 8) (key-size 52))]
    [(or 'argon2d 'argon2i 'argon2id)
     `((t 4) (m ,(expt 2 16)) (p 1) (key-size 71))]
    [_ '()]))

(define (get-pwhash-config spec)
  (match spec
    [(list 'pbkdf2 'hmac (or 'sha1 'sha256 'sha512))
     `((iterations #e2e3))]
    ['scrypt
     '((ln 15) (r 8) (p 1))]
    [(or 'argon2i 'argon2d 'argon2id)
     `((t 100) (m 512) (p 1))]
    [_ #f]))

(define key #"the morning sun is shining like a red rubber ball")
(define badkey #"row row row your boat")
(define salt #"1234567890123456")

(define bad-pwh "$invalid$abc=123$1234$5678")
(define unsupported-pwh "$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m")

;; ============================================================

(module+ main
  (require racket/cmdline crypto/all)
  (run-tests (lambda ()
               (for ([factory (in-list all-factories)])
                 (test #:name (format "~s" (send factory get-name))
                   (test-factory-kdfs factory))))
             #:progress? #t))
