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

(define decaf-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'decaf-read-key))))

;; ============================================================
;; Ed25519

(define decaf-eddsa-impl%
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
        [(ed25519 ed448) (new pk-eddsa-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (case curve
        [(ed25519)
         (define priv (crypto-random-bytes DECAF_EDDSA_25519_PRIVATE_BYTES))
         (define pub (decaf_ed25519_derive_public_key priv))
         (new decaf-ed25519-key% (impl this) (pub pub) (priv priv))]
        [(ed448)
         (define priv (crypto-random-bytes DECAF_EDDSA_448_PRIVATE_BYTES))
         (define pub (decaf_ed448_derive_public_key priv))
         (new decaf-ed448-key% (impl this) (pub pub) (priv priv))]))

    ;; ---- EdDSA ----

    (define/override (make-params curve)
      (case curve
        [(ed25519 ed448) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(ed25519)
         (define pub (make-sized-copy DECAF_EDDSA_25519_PUBLIC_BYTES qB))
         (new decaf-ed25519-key% (impl this) (pub qB) (priv #f))]
        [(ed448)
         (define pub (make-sized-copy DECAF_EDDSA_448_PUBLIC_BYTES qB))
         (new decaf-ed448-key% (impl this) (pub qB) (priv #f))]
        [else #f]))

    (define/override (make-private-key curve qB dB)
      (case curve
        [(ed25519)
         (define priv (make-sized-copy DECAF_EDDSA_25519_PRIVATE_BYTES dB))
         (define pub (decaf_ed25519_derive_public_key priv))
         (new decaf-ed25519-key% (impl this) (pub pub) (priv priv))]
        [(ed448)
         (define priv (make-sized-copy DECAF_EDDSA_448_PRIVATE_BYTES dB))
         (define pub (decaf_ed448_derive_public_key priv))
         (new decaf-ed448-key% (impl this) (pub pub) (priv priv))]
        [else #f]))
    ))

(define decaf-ed*-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (abstract get-curve)
    (define/override (is-private?) (and priv #t))
    (define/override (get-params)
      (send impl curve->params (get-curve)))
    (define/override (get-public-key)
      (if priv (send impl make-public-key (get-curve) pub) this))
    (define/override (-write-public-key fmt)
      (encode-pub-eddsa fmt (get-curve) pub))
    (define/override (-write-private-key fmt)
      (encode-priv-eddsa fmt (get-curve) pub priv))
    (define/override (equal-to-key? other)
      (and (is-a? other decaf-ed*-key%)
           (equal? (get-curve) (send other get-curve))
           (equal? pub (get-field pub other))))
    ))

(define decaf-ed25519-key%
  (class decaf-ed*-key%
    (inherit-field impl pub priv)
    (super-new)
    (define/override (get-curve) 'ed25519)
    (define/override (-sign msg _dspec pad)
      (decaf_ed25519_sign priv pub msg (bytes-length msg) 0))
    (define/override (-verify msg _dspec pad sig)
      (check-bytes-length "signature" DECAF_EDDSA_25519_SIGNATURE_BYTES sig this)
      (decaf_ed25519_verify sig pub msg (bytes-length msg) 0))
    ))

(define decaf-ed448-key%
  (class decaf-ed*-key%
    (inherit-field impl pub priv)
    (super-new)
    (define/override (get-curve) 'ed448)
    (define/override (-sign msg _dspec pad)
      (decaf_ed448_sign priv pub msg (bytes-length msg) 0))
    (define/override (-verify msg _dspec pad sig)
      (check-bytes-length "signature" DECAF_EDDSA_448_SIGNATURE_BYTES sig this)
      (decaf_ed448_verify sig pub msg (bytes-length msg) 0))
    ))

;; ============================================================
;; X25519

(define decaf-ecx-impl%
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
        [(x25519 x448) (new pk-ecx-params% (impl this) (curve curve))]
        [else (err/no-curve curve this)]))

    (define/public (generate-key-from-params curve)
      (case curve
        [(x25519)
         (define priv (crypto-random-bytes DECAF_X25519_PRIVATE_BYTES))
         (define pub  (decaf_x25519_derive_public_key priv))
         (new decaf-x25519-key% (impl this) (pub pub) (priv priv))]
        [(x448)
         (define priv (crypto-random-bytes DECAF_X448_PRIVATE_BYTES))
         (define pub  (decaf_x448_derive_public_key priv))
         (new decaf-x448-key% (impl this) (pub pub) (priv priv))]))

    ;; ----

    (define/override (make-params curve)
      (case curve
        [(x25519 x448) (curve->params curve)]
        [else #f]))

    (define/override (make-public-key curve qB)
      (case curve
        [(x25519)
         (define pub (make-sized-copy DECAF_X25519_PUBLIC_BYTES qB))
         (new decaf-x25519-key% (impl this) (pub qB) (priv #f))]
        [(x448)
         (define pub (make-sized-copy DECAF_X448_PUBLIC_BYTES qB))
         (new decaf-x448-key% (impl this) (pub qB) (priv #f))]
        [else #f]))

    (define/override (make-private-key curve _qB dB)
      (case curve
        [(x25519)
         (define priv (make-sized-copy DECAF_X25519_PRIVATE_BYTES dB))
         (define pub  (decaf_x25519_derive_public_key priv))
         (new decaf-x25519-key% (impl this) (pub pub) (priv priv))]
        [(x448)
         (define priv (make-sized-copy DECAF_X448_PRIVATE_BYTES dB))
         (define pub  (decaf_x448_derive_public_key priv))
         (new decaf-x448-key% (impl this) (pub pub) (priv priv))]
        [else #f]))
    ))

(define decaf-x*-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (abstract get-curve)
    (define/override (is-private?) (and priv #t))
    (define/override (get-params)
      (send impl curve->params (get-curve)))
    (define/override (get-public-key)
      (if priv (send impl make-public-key (get-curve) pub) this))
    (define/override (-write-public-key fmt)
      (encode-pub-ecx fmt (get-curve) pub))
    (define/override (-write-private-key fmt)
      (encode-priv-ecx fmt (get-curve) pub priv))
    (define/override (equal-to-key? other)
      (and (is-a? other decaf-x*-key%)
           (equal? (get-curve) (send other get-curve))
           (equal? pub (get-field pub other))))
    ))

(define decaf-x25519-key%
  (class decaf-x*-key%
    (inherit-field impl priv pub)
    (super-new)
    (define/override (get-curve) 'x25519)
    (define/override (-compute-secret peer-pubkey)
      (define peer-pub
        (cond [(bytes? peer-pubkey)
               (make-sized-copy DECAF_X25519_PUBLIC_BYTES peer-pubkey)]
              [else (get-field pub peer-pubkey)]))
      (or (decaf_x25519 peer-pub priv)
          (crypto-error "operation failed")))
    ))

(define decaf-x448-key%
  (class decaf-x*-key%
    (inherit-field impl priv pub)
    (super-new)
    (define/override (get-curve) 'x448)
    (define/override (-compute-secret peer-pubkey)
      (define peer-pub
        (cond [(bytes? peer-pubkey)
               (make-sized-copy DECAF_X448_PUBLIC_BYTES peer-pubkey)]
              [else (get-field pub peer-pubkey)]))
      (or (decaf_x448 peer-pub priv)
          (crypto-error "operation failed")))
    ))
