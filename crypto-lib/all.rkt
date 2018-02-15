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
(require "private/common/factory.rkt"
         "libcrypto.rkt"
         "gcrypt.rkt"
         "nettle.rkt"
         "argon2.rkt"
         "sodium.rkt")
(provide all-factories
         use-all-factories!)

(define all-factories
  (list nettle-factory
        gcrypt-factory
        argon2-factory
        sodium-factory
        libcrypto-factory))

(define (use-all-factories!)
  (crypto-factories all-factories))
