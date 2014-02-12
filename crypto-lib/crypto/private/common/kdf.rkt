;; Copyright 2014 Ryan Culpepper
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
         "random.rkt"
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
   (->* [bytes?
         bytes?
         #:digest digest-spec?
         #:iterations exact-positive-integer?]
        [#:key-size exact-positive-integer?]
        bytes?)]
  [bcrypt
   (->* [bytes?
         bytes?
         #:cost exact-positive-integer?]
        []
        bytes?)]
  [scrypt
   (->* [bytes?
         bytes?
         #:N exact-positive-integer?]
        [#:p exact-positive-integer?
         #:key-size exact-positive-integer?]
        bytes?)]
  ))

(define (-get-impl o)
  (cond [(kdf-spec? o)
         (or (get-kdf o) (err/missing-kdf o))]
        [else (get-impl* o)]))

(define (kdf k pass salt [params '()])
  (with-crypto-entry 'kdf
    (let ([k (-get-impl k)])
      (send k kdf params pass salt))))

(define (pbkdf2-hmac pass salt
                     #:digest di
                     #:iterations iterations
                     #:key-size [key-size (digest-size di)])
  (with-crypto-entry 'pbkdf2-hmac
    (let ([k (-get-impl `(pbkdf2 hmac ,di))])
      (send k kdf `((iterations ,iterations) (key-size ,key-size)) pass salt))))

(define (bcrypt pass salt
                #:cost cost)
  (with-crypto-entry 'bcrypt
    (let ([k (-get-impl 'bcrypt)])
      (send k kdf `((cost ,cost)) pass salt))))

(define (scrypt pass salt
                #:N N
                #:p [p 1]
                #:r [r 8]
                #:key-size [key-size 32])
  (with-crypto-entry 'scrypt
    (let ([k (-get-impl 'scrypt)])
      (send k kdf `((N ,N) (p ,p) (r ,r) (key-size ,key-size))
            pass salt))))

#|
pbkdf2(digest-for-hmac, iterations, desired-output-size | salt, passphrase)

scrypt(cost-param-N, parallel-param-p, block-size=8, desired-output-size | salt, passphrase)
  gcrypt fixes block-size=8

bcrypt(cost, ??? | salt, passphrase)
   iterations = 2^cost
   -> produces 24 bytes of key material
      as password hash, usually concat BCRYT_VERSION_ID+cost+salt+key 


(get-kdf kdf-spec params)
-> (salt passphrase -> key)

params for '(pbkdf2 hmac <digest>)
  - 'iterations
  - 'key-size = (digest-size digest)

params for 'bcrypt
  - 'cost
  - ???

params for 'scrypt
  - 'cost
  - 'parallel-???
  - 'block-size ??? (gcrypt allows only 8)
  - 'key-size = ???
|#
