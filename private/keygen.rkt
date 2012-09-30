;; mzcrypto: libcrypto bindings for PLT-scheme
;; generic key generation
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.
#lang racket/base
(require "macros.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "dh.rkt")
(provide (all-defined-out))

(define (generate-key algo . params)
  (apply (cond [(!cipher? algo) generate-cipher-key]
               [(!pkey? algo) generate-pkey]
               [(!digest? algo) generate-hmac-key]
               [(!dh? algo) generate-dhkey]
               [else (raise-type-error 'generate-key "crypto type" algo)])
         algo params))

(define-symbols keygen.symbols generate-key)
(define-provider provide-keygen keygen.symbols)
