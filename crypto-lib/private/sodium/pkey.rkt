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
(require ffi/unsafe
         racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/catalog.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

;; ============================================================

;; Ed25519

(define sodium-ed25519-impl%
  (class pk-impl-base%
    (inherit-field spec factory)
    (super-new (spec 'eddsa))

    (define/override (can-sign? pad dspec)
      (eprintf "can-sign? ~e, ~e\n" pad dspec)
      (and (memq pad '(#f)) (memq dspec '(#f sha512))))
    (define/override (has-params?) #f)

    (define/override (generate-key config)
      (check-config config config:eddsa-keygen "EdDSA key generation")
      (define curve (config-ref config 'curve))
      (case curve
        [(ed25519)
         (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
         (define pub  (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
         (define status (crypto_sign_ed25519_keypair pub priv))
         (unless status (crypto-error "key generation failed"))
         (new sodium-ed25519-key% (impl this) (pub pub) (priv priv))]
        [else (crypto-error "unsupported curve\n  curve: ~e" curve)]))
    ))

(define sodium-ed25519-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new sodium-ed25519-key% (impl impl) (pub pub) (priv #f)) this))

    (define/override (-write-key fmt)
      (error 'nope))

    (define/override (equal-to-key? other)
      (and (is-a? other sodium-ed25519-key%)
           (error 'nope)))

    (define/override (-sign msg _dspec pad)
      (define sig (make-bytes crypto_sign_ed25519_BYTES))
      (define s (crypto_sign_ed25519_detached sig msg (bytes-length msg) priv))
      (unless s (crypto-error "failed"))
      sig)

    (define/override (-verify msg _dspec pad sig)
      (crypto_sign_ed25519_verify_detached sig msg (bytes-length msg) pub))
    ))
