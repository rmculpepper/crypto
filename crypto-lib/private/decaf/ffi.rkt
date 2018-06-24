;; Copyright 2018-2019 Ryan Culpepper
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
         ffi/unsafe/define)
(provide (protect-out (all-defined-out)))

(define libdecaf (ffi-lib "libdecaf" '(#f) #:fail (lambda () #f)))

(define-ffi-definer define-decaf libdecaf
  #:default-make-fail make-not-available)

(define ((K v) . as) v)

(define (decaf-is-ok?)
  (and libdecaf (not (eq? DECAF_ED25519_NO_CONTEXT 'missing))))

;; ============================================================
;; common

(define DECAF_WORD_BITS 64)   ;; 64 or 32
(define _decaf_word  _uint64) ;; or _uint32
(define _decaf_sword _int64)  ;; or _int32
(define _decaf_bool  _uint64) ;; or _uint32; either 0 or all ones (#xFF..FF)

(define _decaf_dword  _uint64)
(define _decaf_dsword _int64)

(define _decaf_error _int) ;; 0 = failure, -1 = success
(define (decaf-ok? err) (= err -1))

;; ============================================================
;; sha512

(define-cstruct _decaf_sha512_ctx_s
  ([state (_array _uint64 8)]
   [block (_array _uint8  128)]
   [procd _uint64]))

(define _decaf_sha512_ctx _decaf_sha512_ctx_s-pointer)

(define (new-decaf_sha512_ctx)
  (define p (malloc _decaf_sha512_ctx_s))
  (cpointer-push-tag! p decaf_sha512_ctx_s-tag)
  p)

(define-decaf decaf_sha512_init
  (_fun _decaf_sha512_ctx -> _void))
(define-decaf decaf_sha512_update
  (_fun _decaf_sha512_ctx (msg : _pointer) (mlen : _size) -> _void))
(define-decaf decaf_sha512_final
  (_fun _decaf_sha512_ctx (out : _pointer) (olen : _size) -> _void))

;; ============================================================
;; ed25519

(define-decaf DECAF_ED25519_NO_CONTEXT _pointer
  #:fail (lambda () 'missing))

;; Number of bytes in an EdDSA public key.
(define DECAF_EDDSA_25519_PUBLIC_BYTES 32)

;; Number of bytes in an EdDSA private key.
(define DECAF_EDDSA_25519_PRIVATE_BYTES DECAF_EDDSA_25519_PUBLIC_BYTES)

;; Number of bytes in an EdDSA private key.
(define DECAF_EDDSA_25519_SIGNATURE_BYTES
  (+ DECAF_EDDSA_25519_PUBLIC_BYTES DECAF_EDDSA_25519_PRIVATE_BYTES))

;; EdDSA key generation.  This function uses a different (non-Decaf) encoding.
(define-decaf decaf_ed25519_derive_public_key
  (_fun (pub  : _bytes = (make-bytes DECAF_EDDSA_25519_PUBLIC_BYTES))
        (priv : _pointer) ;; DECAF_EDDSA_25519_PRIVATE_BYTES
        -> _void -> pub))

;; EdDSA signing.
(define-decaf decaf_ed25519_sign
  (_fun (sig : _bytes = (make-bytes DECAF_EDDSA_25519_SIGNATURE_BYTES))
        (priv : _pointer)
        (pub  : _pointer)
        (msg : _pointer) (mlen : _size)
        (ph? : _uint8)
        (ctx : _pointer = DECAF_ED25519_NO_CONTEXT)
        (ctxlen : _uint8 = 0)
        -> _void -> sig))

;; EdDSA signature verification.
(define-decaf decaf_ed25519_verify
  (_fun (sig : _pointer)
        (pub : _pointer)
        (msg : _pointer) (mlen : _size)
        (ph? : _uint8)
        (ctx : _pointer = DECAF_ED25519_NO_CONTEXT)
        (ctxlen : _uint8 = 0)
        -> (err : _decaf_error) -> (decaf-ok? err)))

;; EdDSA to ECDH public key conversion: Deserialize the point to get y
;; on Edwards curve, convert it to u coordinate on Montgomery curve.
;; WARNING: This function does not check that the public key being converted
;; is a valid EdDSA public key (FUTURE?)
(define-decaf decaf_ed25519_convert_public_key_to_x25519
  (_fun (xpub  : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        (edpub : _pointer)
        -> _void -> xpub))

;; EdDSA to ECDH private key conversion: Using the appropriate hash
;; function, hash the EdDSA private key and keep only the lower bytes
;; to get the ECDH private key.
(define-decaf decaf_ed25519_convert_private_key_to_x25519
  (_fun (xpriv  : _bytes = (make-bytes DECAF_X25519_PRIVATE_BYTES))
        (edpriv : _pointer)
        -> _void -> xpriv))


;; ============================================================
;; x25519

;; Number of bytes in an x25519 public key
(define DECAF_X25519_PUBLIC_BYTES 32)

;; Number of bytes in an x25519 private key
(define DECAF_X25519_PRIVATE_BYTES 32)

;; RFC 7748 Diffie-Hellman scalarmul, used to compute shared secrets.
;; This function uses a different (non-Decaf) encoding.
(define-decaf decaf_x25519
  (_fun (out : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        (base : _bytes) ;; DECAF_X25519_PUBLIC_BYTES
        (scalar : _bytes) ;; DECAF_X25519_PRIVATE_BYTES
        -> (s : _decaf_error) -> (and (decaf-ok? s) out)))

;; The base point for X25519 Diffie-Hellman
(define-decaf decaf_x25519_base_point _pointer #:fail (K #f))
;; extern const uint8_t decaf_x25519_base_point[DECAF_X25519_PUBLIC_BYTES];

;; RFC 7748 Diffie-Hellman base point scalarmul.  This function uses a
;; different (non-Decaf) encoding.
(define-decaf decaf_x25519_derive_public_key
  (_fun (out : _bytes = (make-bytes DECAF_X25519_PUBLIC_BYTES))
        (scalar : _pointer) ;; DECAF_X25519_PRIVATE_BYTES
        -> _void -> out))


;; ============================================================
;; ed448

;; Number of bytes in an EdDSA public key.
(define DECAF_EDDSA_448_PUBLIC_BYTES 57)

;; Number of bytes in an EdDSA private key.
(define DECAF_EDDSA_448_PRIVATE_BYTES DECAF_EDDSA_448_PUBLIC_BYTES)

;; Number of bytes in an EdDSA private key.
(define DECAF_EDDSA_448_SIGNATURE_BYTES
  (+ DECAF_EDDSA_448_PUBLIC_BYTES DECAF_EDDSA_448_PRIVATE_BYTES))

;; EdDSA key generation.  This function uses a different (non-Decaf) encoding.
(define-decaf decaf_ed448_derive_public_key
  (_fun (pub  : _bytes = (make-bytes DECAF_EDDSA_448_PUBLIC_BYTES))
        (priv : _pointer) ;; DECAF_EDDSA_448_PRIVATE_BYTES
        -> _void -> pub))

;; EdDSA signing.
(define-decaf decaf_ed448_sign
  (_fun (sig : _bytes = (make-bytes DECAF_EDDSA_448_SIGNATURE_BYTES))
        (priv : _pointer)
        (pub  : _pointer)
        (msg : _pointer) (mlen : _size)
        (ph? : _uint8)
        (ctx : _pointer = #f) (ctxlen : _uint8 = 0)
        -> _void -> sig))

;; EdDSA signature verification.
(define-decaf decaf_ed448_verify
  (_fun (sig : _pointer)
        (pub : _pointer)
        (msg : _pointer) (mlen : _size)
        (ph? : _uint8)
        (ctx : _pointer = #f) (ctxlen : _uint8 = 0)
        -> (err : _decaf_error) -> (decaf-ok? err)))

;; EdDSA to ECDH public key conversion: Deserialize the point to get y
;; on Edwards curve, convert it to u coordinate on Montgomery curve.
;; WARNING: This function does not check that the public key being converted
;; is a valid EdDSA public key (FUTURE?)
(define-decaf decaf_ed448_convert_public_key_to_x448
  (_fun (xpub  : _bytes = (make-bytes DECAF_X448_PUBLIC_BYTES))
        (edpub : _pointer)
        -> _void -> xpub))

;; EdDSA to ECDH private key conversion: Using the appropriate hash
;; function, hash the EdDSA private key and keep only the lower bytes
;; to get the ECDH private key.
(define-decaf decaf_ed448_convert_private_key_to_x448
  (_fun (xpriv  : _bytes = (make-bytes DECAF_X448_PRIVATE_BYTES))
        (edpriv : _pointer)
        -> _void -> xpriv))


;; ============================================================
;; x448

;; Number of bytes in an x448 public key
(define DECAF_X448_PUBLIC_BYTES 56)

;; Number of bytes in an x448 private key
(define DECAF_X448_PRIVATE_BYTES 56)

;; RFC 7748 Diffie-Hellman scalarmul, used to compute shared secrets.
;; This function uses a different (non-Decaf) encoding.
(define-decaf decaf_x448
  (_fun (out : _bytes = (make-bytes DECAF_X448_PUBLIC_BYTES))
        (base : _bytes) ;; DECAF_X448_PUBLIC_BYTES
        (scalar : _bytes) ;; DECAF_X448_PRIVATE_BYTES
        -> (s : _decaf_error) -> (and (decaf-ok? s) out)))

;; The base point for X448 Diffie-Hellman
(define-decaf decaf_x448_base_point _pointer #:fail (K #f))
;; extern const uint8_t decaf_x448_base_point[DECAF_X448_PUBLIC_BYTES];

;; RFC 7748 Diffie-Hellman base point scalarmul.  This function uses a
;; different (non-Decaf) encoding.
(define-decaf decaf_x448_derive_public_key
  (_fun (out : _bytes = (make-bytes DECAF_X448_PUBLIC_BYTES))
        (scalar : _pointer) ;; DECAF_X448_PRIVATE_BYTES
        -> _void -> out))

;; ============================================================
