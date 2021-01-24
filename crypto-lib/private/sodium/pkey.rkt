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
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

;; Size of serialized public and private key components.
(define KEYSIZE 32)

(define sodium-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'sodium-read-key))))

;; ============================================================
;; Ed25519

(define sodium-eddsa-impl%
  (class pk-impl-base%
    (inherit-field spec factory)
    (super-new (spec 'eddsa))

    (define/override (can-sign? pad) (and (memq pad '(#f)) 'nodigest))
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:eddsa-keygen "EdDSA parameters generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (case curve
        [(ed25519) (new pk-eddsa-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (case curve
        [(ed25519)
         (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
         (define pub  (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
         (define status (crypto_sign_ed25519_keypair pub priv))
         (unless status (crypto-error "key generation failed"))
         (new sodium-ed25519-key% (impl this) (pub pub) (priv priv))]))

    ;; ---- EdDSA ----

    (define/override (make-params curve)
      (case curve
        [(ed25519) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(ed25519)
         (define pub (make-sized-copy crypto_sign_ed25519_PUBLICKEYBYTES qB))
         (new sodium-ed25519-key% (impl this) (pub qB) (priv #f))]
        [else #f]))

    (define/override (make-private-key curve qB dB)
      ;; AFAICT, libsodium calls the secret part of the key the "seed",
      ;; and seed_keypair can be used to recompute the public key.
      (case curve
        [(ed25519)
         (define seed (make-sized-copy crypto_sign_ed25519_SEEDBYTES dB))
         (define priv (make-bytes crypto_sign_ed25519_SECRETKEYBYTES))
         (define pub (make-bytes crypto_sign_ed25519_PUBLICKEYBYTES))
         (crypto_sign_ed25519_seed_keypair pub priv seed)
         (unless (equal? seed (subbytes priv 0 32))
           (crypto-error "failed to recompute key from seed"))
         (when qB (check-recomputed-qB pub qB))
         (new sodium-ed25519-key% (impl this) (pub pub) (priv priv))]
        [else #f]))
    ))

(define sodium-ed25519-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-params)
      (send impl curve->params 'ed25519))

    (define/override (get-public-key)
      (if priv (new sodium-ed25519-key% (impl impl) (pub pub) (priv #f)) this))

    (define/override (-write-public-key fmt)
      (encode-pub-eddsa fmt 'ed25519 pub))
    (define/override (-write-private-key fmt)
      (encode-priv-eddsa fmt 'ed25519 pub (subbytes priv 0 32)))

    (define/override (equal-to-key? other)
      (and (is-a? other sodium-ed25519-key%)
           (equal? pub (get-field pub other))))

    (define/override (-sign msg _dspec pad)
      (define sig (make-bytes crypto_sign_ed25519_BYTES))
      (define s (crypto_sign_ed25519_detached sig msg (bytes-length msg) priv))
      (unless s (crypto-error "failed"))
      sig)

    (define/override (-verify msg _dspec pad sig)
      (and (= (bytes-length sig) crypto_sign_ed25519_BYTES)
           (crypto_sign_ed25519_verify_detached sig msg (bytes-length msg) pub)))
    ))

;; ============================================================
;; X25519

(define sodium-ecx-impl%
  (class pk-impl-base%
    (inherit-field spec factory)
    (super-new (spec 'ecx))

    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ecx-keygen "EC/X parameters generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (case curve
        [(x25519) (new pk-ecx-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (case curve
        [(x25519)
         (define priv (crypto-random-bytes crypto_scalarmult_curve25519_SCALARBYTES))
         (define pub  (make-bytes crypto_scalarmult_curve25519_BYTES))
         (define status (crypto_scalarmult_curve25519_base pub priv))
         (unless (zero? status) (crypto-error "key generation failed"))
         (new sodium-x25519-key% (impl this) (pub pub) (priv priv))]))

    ;; ----

    (define/override (make-params curve)
      (case curve
        [(x25519) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(x25519)
         (define pub (make-sized-copy crypto_scalarmult_curve25519_BYTES qB))
         (new sodium-x25519-key% (impl this) (pub qB) (priv #f))]
        [else #f]))

    (define/override (make-private-key curve qB dB)
      (case curve
        [(x25519)
         (define priv (make-sized-copy crypto_scalarmult_curve25519_SCALARBYTES dB))
         (define pub (make-bytes crypto_scalarmult_curve25519_BYTES))
         (crypto_scalarmult_curve25519_base pub priv)
         (when qB (check-recomputed-qB pub qB))
         (new sodium-x25519-key% (impl this) (pub pub) (priv priv))]
        [else #f]))
    ))

(define sodium-x25519-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-params)
      (send impl curve->params 'x25519))

    (define/override (get-public-key)
      (if priv (new sodium-x25519-key% (impl impl) (pub pub) (priv #f)) this))

    (define/override (-write-public-key fmt)
      (encode-pub-ecx fmt 'x25519 pub))
    (define/override (-write-private-key fmt)
      (encode-priv-ecx fmt 'x25519 pub priv))

    (define/override (equal-to-key? other)
      (and (is-a? other sodium-x25519-key%)
           (equal? pub (get-field pub other))))

    (define/override (-compute-secret peer-pubkey)
      (define peer-pub
        (cond [(bytes? peer-pubkey)
               (make-sized-copy crypto_scalarmult_curve25519_BYTES peer-pubkey)]
              [else (get-field pub peer-pubkey)]))
      (define secret (make-bytes crypto_scalarmult_curve25519_BYTES))
      (crypto_scalarmult_curve25519 secret priv peer-pub)
      secret)

    (define/override (-compatible-for-key-agree? peer-pubkey)
      #t)

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key 'x25519 bs))
    ))
