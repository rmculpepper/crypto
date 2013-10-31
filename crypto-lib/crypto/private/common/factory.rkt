;; Copyright 2013 Ryan Culpepper
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
         "catalog.rkt")
(provide
 (contract-out
  [crypto-factories
   (parameter/c (listof factory?))]
  [get-digest
   (->* [digest-spec?] [(listof factory?)] (or/c digest-impl? #f))]
  [get-cipher
   (->* [cipher-spec?] [(listof factory?)] (or/c cipher-impl? #f))]
  [get-random
   (-> (or/c random-impl? #f))]
  ))

;; crypto-factories : parameter of (listof factory<%>)
(define crypto-factories (make-parameter null))

(define (get-digest di [factories (crypto-factories)])
  (for/or ([f (in-list factories)])
    (send f get-digest-by-name di)))

(define (get-cipher ci [factories (crypto-factories)])
  (for/or ([f (in-list factories)])
    (send f get-cipher-by-name ci)))

(define (get-random [factories (crypto-factories)])
  (for/or ([f (in-list factories)])
    (send f get-random)))
