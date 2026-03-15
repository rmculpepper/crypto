;; Copyright 2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         checkers
         crypto
         crypto/private/common/catalog
         (prefix-in rkt: crypto/private/rkt/pbkdf2)
         "util.rkt")
(provide test-factory-kdfs
         test-kdfs
         test-kdfs-agree)

(define (test-factory-kdfs factory)
  (test #:name "kdf"
    (test-kdfs factory)))

(define (test-kdfs factory)
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
                   #:error #rx"algorithm does not match")))))))

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
