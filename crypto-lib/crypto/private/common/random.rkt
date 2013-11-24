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
         "factory.rkt")
(provide
 (contract-out
  [random-bytes
   (->* [exact-nonnegative-integer?]
        [random-impl? #:level (or/c 'strong 'very-strong)]
        bytes?)]
  [random-ready?
   (-> random-impl? boolean?)]
  [random-can-add-entropy?
   (-> random-impl? boolean?)]
  [random-add-entropy
   (->* [random-impl? bytes?] [entropy-in-bytes real?]
        void?)]
  ))

(define (random-bytes size [impl (get-random)] #:level [level 'strong])
  (unless impl (error 'random-bytes "no source of randomness given"))
  (let ([buf (make-bytes size)])
    (send impl random-bytes! 'random-bytes buf 0 size level)
    buf))

(define (random-ready? ri)
  (send ri ok?))

(define (random-can-add-entropy? ri)
  (send ri can-add-entropy?))

(define (random-add-entropy ri buf [entropy-in-bytes (bytes-length buf)])
  (unless (send ri can-add-entropy?)
    (error 'random-add-entropy "adding entropy not supported"))
  (unless (<= 0 entropy-in-bytes (bytes-length buf))
    (error 'random-add-entropy
           "entropy estimate out of range\n  range: [0,~s]\n  estimate: ~e"
           (bytes-length buf)
           entropy-in-bytes))
  (send impl add-entropy 'random-add-entropy buf entropy-in-bytes))
