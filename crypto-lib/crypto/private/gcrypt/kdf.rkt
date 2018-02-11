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

    (define/public (kdf params pass salt)
      (define iterations (cadr (assq 'iterations params)))
      (define key-size (cadr (assq 'key-size params)))
      (define md (get-field md di))
      (gcry_kdf_derive pass GCRY_KDF_PBKDF2 md salt iterations key-size))
    ))

(define gcrypt-scrypt-impl%
  (class* impl-base% (kdf-impl<%>)
    (super-new)

    (define/public (kdf params pass salt)
      (define N (cadr (assq 'N params)))
      (define p (cadr (assq 'p params)))
      (define r (cadr (assq 'r params)))
      (define key-size (cadr (assq 'key-size params)))
      ;; FIXME: assert r = 8
      (unless (equal? r 8)
        (crypto-error "bad value for scrypt r parameter\n  r: ~e" r))
      (gcry_kdf_derive pass GCRY_KDF_SCRYPT N salt p key-size))
    ))
