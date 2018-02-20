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
