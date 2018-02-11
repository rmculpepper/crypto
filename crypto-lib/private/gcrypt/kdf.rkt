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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide gcrypt-pbkdf2-impl%
         gcrypt-scrypt-impl%)

(define gcrypt-pbkdf2-impl%
  (class* impl-base% (kdf-impl<%>)
    (init-field di)
    (inherit-field spec)
    (super-new)

    (define/public (kdf config pass salt)
      (check-config config config:pbkdf2 "PBKDF2")
      (define iters    (config-ref config 'iterations))
      (define key-size (config-ref config 'key-size))
      (define md (get-field md di))
      (gcry_kdf_derive pass GCRY_KDF_PBKDF2 md salt iters key-size))
    ))

(define gcrypt-scrypt-impl%
  (class* impl-base% (kdf-impl<%>)
    (super-new)

    (define/public (kdf config pass salt)
      (check-config config config:scrypt "scrypt")
      (define N (config-ref config 'N))
      (define p (config-ref config 'p 1))
      (define r (config-ref config 'r 8))
      (define key-size (config-ref config 'key-size))
      (unless (equal? r 8)
        (crypto-error "bad value for scrypt r parameter\n  r: ~e" r))
      (gcry_kdf_derive pass GCRY_KDF_SCRYPT N salt p key-size))
    ))
