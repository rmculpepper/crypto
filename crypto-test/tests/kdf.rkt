;; Copyright 2018 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require racket/class
         racket/match
         checktest
         crypto
         crypto/private/common/catalog
         (prefix-in rkt: crypto/private/rkt/pbkdf2)
         "util.rkt")
(provide test-kdfs
         test-kdfs-agree)

(define (test-kdfs factory)
  (for ([name (list-known-kdfs)])
    (define impl (send factory get-kdf name))
    (when impl
      ;; Test KDF
      (define config (get-config name))
      (test #:name (format "kdf ~v" name)
        (let ([salt (and (send impl salt-allowed?) salt)])
          (check (kdf impl key salt config) bytes?)
          (match name
            [(list 'pbkdf2 'hmac di)
             (define dimpl (send factory get-digest di))
             (when dimpl
               (check-equal? (kdf impl key salt '((iterations 2000) (key-size 89)))
                             (rkt:pbkdf2-hmac dimpl key salt 2000 89)))]
            [_ (void)])))
      ;; Test pwhash
      (define pwconfig (get-pwhash-config name))
      (when pwconfig
        (test #:name (format "pwhash ~v" name)
          (define cred (pwhash impl key pwconfig))
          (check-equal? (pwhash-verify impl key cred) #t)
          (check-equal? (pwhash-verify impl badkey cred) #f)
          (check-raise (pwhash-verify impl key bad-pwh)
                       #rx"algorithm does not match")
          (check-raise (pwhash-verify impl key unsupported-pwh)
                       #rx"algorithm does not match"))))))

(define (test-kdfs-agree factories)
  (for ([name (list-known-kdfs)])
    (define config (get-config name))
    (define pwconfig (get-pwhash-config name))
    (define impls
      (filter values
              (for/list ([factory factories])
                (send factory get-kdf name))))
    (test #:name (format "agreement for kdf ~v" name)
      #:pre (case (length impls)
              [(0) (skip-test "no impl")]
              [(1) (skip-test (format "only one impl: ~v" (car impls)))])
      (define impl0 (car impls))
      (define salt* (and (send impl0 salt-allowed?) salt))
      (define r0 (kdf impl0 key salt* config))
      (define cred0 (and pwconfig (pwhash impl0 key pwconfig)))
      (for ([impl (cdr impls)])
        (check-equal? (kdf impl key salt* config) r0)
        (when pwconfig
          (test #:name "pwhash agreement"
            (check-equal? (pwhash-verify impl key cred0) #t)
            (check-equal? (pwhash-verify impl badkey cred0) #f)
            (define cred1 (pwhash impl key pwconfig))
            (check-equal? (pwhash-verify impl0 key cred1) #t)
            (check-equal? (pwhash-verify impl0 badkey cred1) #f)))))))

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
