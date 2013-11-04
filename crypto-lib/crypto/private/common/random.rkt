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
   (->* [exact-nonnegative-integer?] [random-impl?] bytes?)]
  [pseudo-random-bytes
   (->* [exact-nonnegative-integer?] [random-impl?] bytes?)]))

(define (random-bytes size [impl (get-random)])
  (unless impl (error 'random-bytes "no source of randomness given"))
  (let ([buf (make-bytes size)])
    (send impl random-bytes! 'random-bytes buf 0 size)
    buf))

(define (pseudo-random-bytes size [impl (get-random)])
  (unless impl (error 'pseudo-random-bytes "no source of randomness given"))
  (let ([buf (make-bytes size)])
    (send impl pseudo-random-bytes! 'pseudo-random-bytes buf 0 size)
    buf))
