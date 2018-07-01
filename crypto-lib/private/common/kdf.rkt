;; Copyright 2014-2018 Ryan Culpepper
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
         racket/contract/base
         "interfaces.rkt"
         "catalog.rkt"
         "factory.rkt"
         "common.rkt"
         "error.rkt"
         "digest.rkt")
(provide
 (contract-out
  [kdf
   (->* [(or/c kdf-spec? kdf-impl?)
         bytes?
         bytes?]
        [(listof (list/c symbol? any/c))]
        bytes?)]
  [pwhash
   (->* [(or/c kdf-spec? kdf-impl?) bytes?]
        [(listof (list/c symbol? any/c))]
        string?)]
  [pwhash-verify
   (-> (or/c kdf-impl? #f) bytes? string?
       boolean?)]
  [pbkdf2-hmac
   (->* [digest-spec? bytes? bytes? #:iterations exact-positive-integer?]
        [#:key-size exact-positive-integer?]
        bytes?)]
  #|
  [bcrypt
   (->* [bytes?
         bytes?
         #:cost exact-positive-integer?]
        []
        bytes?)]
  |#
  [scrypt
   (->* [bytes?
         bytes?
         #:N exact-positive-integer?]
        [#:p exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  ))

(define (-get-impl o) (to-impl o #:what "KDF" #:lookup get-kdf))

(define (kdf k pass salt [params '()])
  (with-crypto-entry 'kdf
    (let ([k (-get-impl k)])
      (send k kdf params pass salt))))

(define (pwhash k pass [params '()])
  (with-crypto-entry 'pwhash
    (let ([k (-get-impl k)])
      (send k pwhash params pass))))

(define (pwhash-verify k pass cred)
  (with-crypto-entry 'pwhash-verify
    (define k* (or k (-get-impl (pwcred->kdf-spec cred))))
    (send k* pwhash-verify pass cred)))

(define (pwcred->kdf-spec cred)
  ;; see also crypto/private/rkt/pwhash
  (define m (regexp-match #rx"^[$]([a-z0-9-]*)[$]" cred))
  (define id (and m (string->symbol (cadr m))))
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2) '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [(#f) (crypto-error "invalid password hash format")]
    [else (crypto-error "unknown password hash identifier\n  id: ~e" id)]))


(define (pbkdf2-hmac di pass salt
                     #:iterations iterations
                     #:key-size [key-size (digest-size di)])
  (with-crypto-entry 'pbkdf2-hmac
    (let ([k (-get-impl `(pbkdf2 hmac ,di))])
      (send k kdf `((iterations ,iterations) (key-size ,key-size)) pass salt))))

#|
(define (bcrypt pass salt
                #:cost cost)
  (with-crypto-entry 'bcrypt
    (let ([k (-get-impl 'bcrypt)])
      (send k kdf `((cost ,cost)) pass salt))))
|#

(define (scrypt pass salt
                #:N N
                #:p [p 1]
                #:r [r 8]
                #:key-size [key-size 32])
  (with-crypto-entry 'scrypt
    (let ([k (-get-impl 'scrypt)])
      (send k kdf `((N ,N) (p ,p) (r ,r) (key-size ,key-size))
            pass salt))))
