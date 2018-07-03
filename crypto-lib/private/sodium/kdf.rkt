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
         racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "../common/util.rkt"
         "ffi.rkt")
(provide sodium-argon2-impl%
         sodium-scrypt-impl%)

;; ----------------------------------------

(define sodium-argon2-impl%
  (class kdf-impl-base%
    (inherit-field spec)
    (inherit about)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (t mkb p key-size)
        (check/ref-config '(t m p key-size) config config:argon2-kdf "argon2"))
      (unless (equal? p 1)
        (crypto-error "implementation restriction;\n parallelism must be 1\n  given: ~e\n  kdf: ~a"
                      p (about)))
      (define m (* mkb 1024))
      (unless (= (bytes-length salt) crypto_pwhash_argon2id_SALTBYTES)
        (crypto-error "salt must be ~s bytes\n  given: ~s bytes\n  kdf: ~a"
                      crypto_pwhash_argon2id_SALTBYTES (bytes-length salt) (about)))
      (define out (make-bytes key-size))
      (define alg (get-alg))
      (define status (crypto_pwhash out key-size pass (bytes-length pass) salt t m alg))
      (unless (zero? status)
        (crypto-error "key derivation failed\n  kdf: ~a" (about)))
      out)

    (define/override (pwhash config pass)
      (define-values (t mkb p)
        (check/ref-config '(t m p) config config:argon2-base "argon2"))
      (unless (equal? p 1)
        (crypto-error "implementation restriction;\n parallelism must be 1\n  given: ~e\n  kdf: ~a"
                      p (about)))
      (define m (* 1024 mkb))
      (define alg (get-alg))
      (define out (make-bytes (crypto_pwhash_strbytes)))
      (define status (crypto_pwhash_str_alg out pass (bytes-length pass) t m alg))
      (unless (zero? status) (crypto-error "failed: ~e" status))
      (cast out _bytes _string/latin-1))

    (define/override (pwhash-verify pass cred)
      (define alg (get-alg))
      (define status (crypto_pwhash_str_verify cred pass (bytes-length pass)))
      (zero? status))

    (define/private (get-alg)
      (case spec
        [(argon2i) crypto_pwhash_ALG_ARGON2I13]
        [(argon2id) crypto_pwhash_ALG_ARGON2ID13]))
    ))

(define sodium-scrypt-impl%
  (class kdf-impl-base%
    (inherit about)
    (super-new)

    (define/override (kdf config pass salt)
      (define-values (N ln p r key-size)
        (check/ref-config '(N ln p r key-size) config config:scrypt-kdf "scrypt"))
      (define N* (or N (expt 2 ln)))
      (define out (make-bytes key-size))
      (define status
        (crypto_pwhash_scryptsalsa208sha256_ll pass (bytes-length pass)
                                               salt (bytes-length salt)
                                               N r p
                                               out key-size))
      (unless (zero? status)
        (crypto-error "key derivation failed\n  kdf: ~a" (about)))
      out)

    (define/override (pwhash config pass)
      (kdf-pwhash-scrypt this config pass))
    (define/override (pwhash-verify pass cred)
      (kdf-pwhash-verify this pass cred))
    ))
