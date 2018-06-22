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
(require racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide sodium-argon2-impl%
         sodium-scrypt-impl%)

;; ----------------------------------------

(define sodium-argon2-impl%
  (class* impl-base% (kdf-impl<%>)
    (inherit-field spec)
    (inherit about)
    (super-new)
    (define/public (kdf config pass salt)
      (check-config config config:argon2 "argon2")
      (define t (config-ref config 't))
      (define m (config-ref config 'm)) ;; in kb
      (define p (config-ref config 'p 1))
      (define key-size (config-ref config 'key-size 32))
      (unless (equal? p 1)
        (crypto-error "parallelism must be 1\n  given: ~e\n  kdf: ~a" p (about)))
      (unless (= (bytes-length salt) crypto_pwhash_argon2id_SALTBYTES)
        (crypto-error "salt must be ~s bytes\n  given: ~s bytes\n  kdf: ~a"
                      crypto_pwhash_argon2id_SALTBYTES (about)))
      (define out (make-bytes key-size))
      (define status
        (crypto_pwhash out key-size
                       pass (bytes-length pass)
                       salt
                       t (* m 1024)
                       (case spec
                         [(argon2i) crypto_pwhash_ALG_ARGON2I13]
                         [(argon2id) crypto_pwhash_ALG_ARGON2ID13])))
      (unless (zero? status)
        (crypto-error "key derivation failed\n  kdf: ~a" (about)))
      out)))

(define sodium-scrypt-impl%
  (class* impl-base% (kdf-impl<%>)
    (inherit about)
    (super-new)
    (define/public (kdf config pass salt)
      (check-config config config:scrypt "scrypt")
      (define N (config-ref config 'N))
      (define p (config-ref config 'p 1))
      (define r (config-ref config 'r 8))
      (define key-size (config-ref config 'key-size))
      (define out (make-bytes key-size))
      (define status
        (crypto_pwhash_scryptsalsa208sha256_ll pass (bytes-length pass)
                                               salt (bytes-length salt)
                                               N r p
                                               out key-size))
      (unless (zero? status)
        (crypto-error "key derivation failed\n  kdf: ~a" (about)))
      out)))
