;; Copyright 2013-2014 Ryan Culpepper
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
         racket/contract
         "interfaces.rkt"
         "error.rkt"
         "catalog.rkt")
(provide
 (contract-out
  [crypto-factories
   (parameter/c (listof crypto-factory?))]
  [get-factory
   (-> (or/c digest-impl? digest-ctx?
             cipher-impl? cipher-ctx?
             random-impl?
             pk-impl? pk-parameters? pk-key?)
       crypto-factory?)]
  [get-digest
   (->* [digest-spec?] [factories/c] (or/c digest-impl? #f))]
  [get-cipher
   (->* [cipher-spec?] [factories/c] (or/c cipher-impl? #f))]
  [get-pk
   (->* [symbol?] [factories/c] (or/c pk-impl? #f))]
  [get-random
   (->* [] [factories/c] (or/c random-impl? #f))]
  ))

(define factories/c (or/c crypto-factory? (listof crypto-factory?)))

;; crypto-factories : parameter of (listof factory<%>)
(define crypto-factories (make-parameter null))

(define (get-factory i)
  (with-crypto-entry 'get-factory
    (let loop ([i i])
      (cond [(is-a? i impl<%>) (send i get-factory)]
            [(is-a? i ctx<%>) (loop (send i get-impl))]))))

(define (get-digest di [factory/s (crypto-factories)])
  (with-crypto-entry 'get-digest
    (for/or ([f (in-list (if (list? factory/s) factory/s (list factory/s)))])
      (send f get-digest di))))

(define (get-cipher ci [factory/s (crypto-factories)])
  (with-crypto-entry 'get-cipher
    (for/or ([f (in-list (if (list? factory/s) factory/s (list factory/s)))])
      (send f get-cipher ci))))

(define (get-pk pki [factory/s (crypto-factories)])
  (with-crypto-entry 'get-pk
    (for/or ([f (in-list (if (list? factory/s) factory/s (list factory/s)))])
      (send f get-pk pki))))

(define (get-random [factory/s (crypto-factories)])
  (with-crypto-entry 'get-random
    (for/or ([f (in-list (if (list? factory/s) factory/s (list factory/s)))])
      (send f get-random))))
