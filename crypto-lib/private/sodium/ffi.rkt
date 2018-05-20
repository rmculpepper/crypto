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
         ffi/unsafe/define)
(provide (protect-out (all-defined-out)))

(define libsodium (ffi-lib "libsodium" '(#f "23" "18") #:fail (lambda () #f)))

(define-ffi-definer define-na libsodium
  #:default-make-fail make-not-available)

(define sodium-ok? (and libsodium #t))

(define-na sodium_version_string (_fun -> _string/utf-8)
  #:fail (lambda () (lambda () #f)))
(define-na sodium_library_version_major (_fun -> _int)
  #:fail (lambda () (lambda () 0)))
(define-na sodium_library_version_minor (_fun -> _int)
  #:fail (lambda () (lambda () 0)))
(define-na sodium_library_minimal (_fun -> _int))

;; ============================================================
;; Digests

(define crypto_generichash_blake2b_BYTES_MIN     16)
(define crypto_generichash_blake2b_BYTES_MAX     64)
(define crypto_generichash_blake2b_BYTES         32)
(define crypto_generichash_blake2b_KEYBYTES_MIN  16)
(define crypto_generichash_blake2b_KEYBYTES_MAX  64)
(define crypto_generichash_blake2b_KEYBYTES      32)
(define crypto_generichash_blake2b_SALTBYTES     16)
(define crypto_generichash_blake2b_PERSONALBYTES 16)
(define crypto_generichash_blake2b_STATEBYTES   384)

(define-na crypto_generichash_blake2b_bytes_min (_fun -> _size))
(define-na crypto_generichash_blake2b_bytes_max (_fun -> _size))
(define-na crypto_generichash_blake2b_bytes (_fun -> _size))
(define-na crypto_generichash_blake2b_keybytes_min (_fun -> _size))
(define-na crypto_generichash_blake2b_keybytes_max (_fun -> _size))
(define-na crypto_generichash_blake2b_keybytes (_fun -> _size))
(define-na crypto_generichash_blake2b_saltbytes (_fun -> _size))
(define-na crypto_generichash_blake2b_personalbytes (_fun -> _size))
(define-na crypto_generichash_blake2b_statebytes (_fun -> _size)
  #:fail (lambda () (lambda () crypto_generichash_blake2b_STATEBYTES)))

(define-na crypto_generichash_blake2b
  (_fun (out : _bytes) (_size = (bytes-length out))
        (in : _bytes)  (_ullong = (bytes-length in))
        (key : _bytes) (_size = (bytes-length key))
        -> _int))

(define-na crypto_generichash_blake2b_salt_personal
  (_fun (out : _bytes) (_size = (bytes-length out))
        (in : _bytes)  (_ullong = (bytes-length in))
        (key : _bytes) (_size = (bytes-length key))
        (salt : _bytes)
        (pers : _bytes)
        -> _int))

(define-na crypto_generichash_blake2b_init
  (_fun (state : _pointer)
        (key : _bytes) (_size = (bytes-length key))
        (outlen : _size)
        -> _int))

(define-na crypto_generichash_blake2b_init_salt_personal
  (_fun (state : _pointer)
        (key : _bytes) (_size = (bytes-length key))
        (outlen : _size)
        (salt : _bytes)
        (pers : _bytes)
        -> _int))

(define-na crypto_generichash_blake2b_update
  (_fun (state in inlen) ::
        (state : _pointer)
        (in : _pointer)
        (inlen : _ullong)
        -> _int))

(define-na crypto_generichash_blake2b_final
  (_fun (state : _pointer)
        (out : _bytes) (_size = (bytes-length out))
        -> _int)
  #:fail (lambda () #f))

(define blake2-ok? (and crypto_generichash_blake2b_final #t))

;; ============================================================
;; AEAD Ciphers

(define _aead_encrypt_detached_func
  (_fun (c mac m ad npub k) ::
        (c    : _bytes)
        (mac  : _bytes)  (maclen : (_ptr io _ullong) = (bytes-length mac))
        (m    : _bytes)  (_ullong = (bytes-length m))
        (ad   : _bytes)  (_ullong = (bytes-length ad))
        (_pointer = #f)
        (npub : _bytes)
        (k    : _bytes)
        -> (r : _int) -> (and (zero? r) maclen)))

(define _aead_decrypt_detached_func
  (_fun (m c mac ad npub k) ::
        (m    : _bytes)
        (_pointer = #f) ;; no secret nonce
        (c    : _bytes)  (_ullong = (bytes-length c))
        (mac  : _bytes)
        (ad   : _bytes)  (_ullong = (bytes-length ad))
        (npub : _bytes)
        (k : _bytes)
        -> _int))

(struct aeadcipher (spec keysize noncesize authsize encrypt decrypt))

;; ----------------------------------------
;; chacha20-poly1305

;; -- IETF ChaCha20-Poly1305 construction with a 96-bit nonce and a 32-bit internal counter --

(define crypto_aead_chacha20poly1305_ietf_KEYBYTES  32)
(define crypto_aead_chacha20poly1305_ietf_NSECBYTES  0)
(define crypto_aead_chacha20poly1305_ietf_NPUBBYTES 12)
(define crypto_aead_chacha20poly1305_ietf_ABYTES    16)

(define-na crypto_aead_chacha20poly1305_ietf_keybytes  (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_ietf_nsecbytes (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_ietf_npubbytes (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_ietf_abytes    (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_ietf_messagebytes_max (_fun -> _size))

(define-na crypto_aead_chacha20poly1305_ietf_encrypt_detached
  _aead_encrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_chacha20poly1305_ietf_decrypt_detached
  _aead_decrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_chacha20poly1305_ietf_keygen
  ;; takes crypto_aead_chacha20poly1305_ietf_KEYBYTES bytes
  (_fun _bytes -> _void))

(define chacha20poly1305_ietf-record
  (and crypto_aead_chacha20poly1305_ietf_encrypt_detached
       crypto_aead_chacha20poly1305_ietf_decrypt_detached
       (aeadcipher '(chacha20-poly1305 stream)
                   crypto_aead_chacha20poly1305_ietf_KEYBYTES
                   crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                   crypto_aead_chacha20poly1305_ietf_ABYTES
                   crypto_aead_chacha20poly1305_ietf_encrypt_detached
                   crypto_aead_chacha20poly1305_ietf_decrypt_detached)))

;; -- Original ChaCha20-Poly1305 construction with a 64-bit nonce and a 64-bit internal counter --

(define crypto_aead_chacha20poly1305_KEYBYTES  32)
(define crypto_aead_chacha20poly1305_NSECBYTES  0)
(define crypto_aead_chacha20poly1305_NPUBBYTES  8)
(define crypto_aead_chacha20poly1305_ABYTES    16)

(define-na crypto_aead_chacha20poly1305_keybytes  (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_nsecbytes (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_npubbytes (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_abytes    (_fun -> _size))
(define-na crypto_aead_chacha20poly1305_messagebytes_max (_fun -> _size))

(define-na crypto_aead_chacha20poly1305_encrypt_detached
  _aead_encrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_chacha20poly1305_decrypt_detached
  _aead_decrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_chacha20poly1305_keygen
  ;; takes crypto_aead_chacha20poly1305_KEYBYTES bytes
  (_fun _bytes -> _void))

(define chacha20poly1305-record
  (and crypto_aead_chacha20poly1305_encrypt_detached
       crypto_aead_chacha20poly1305_decrypt_detached
       (aeadcipher '(chacha20-poly1305/iv8 stream)
                   crypto_aead_chacha20poly1305_KEYBYTES
                   crypto_aead_chacha20poly1305_NPUBBYTES
                   crypto_aead_chacha20poly1305_ABYTES
                   crypto_aead_chacha20poly1305_encrypt_detached
                   crypto_aead_chacha20poly1305_decrypt_detached)))

;; ----------------------------------------
;; xchacha20-poly1305

(define crypto_aead_xchacha20poly1305_ietf_KEYBYTES  32)
(define crypto_aead_xchacha20poly1305_ietf_NSECBYTES  0)
(define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24)
(define crypto_aead_xchacha20poly1305_ietf_ABYTES    16)

(define-na crypto_aead_xchacha20poly1305_ietf_keybytes  (_fun -> _size))
(define-na crypto_aead_xchacha20poly1305_ietf_nsecbytes (_fun -> _size))
(define-na crypto_aead_xchacha20poly1305_ietf_npubbytes (_fun -> _size))
(define-na crypto_aead_xchacha20poly1305_ietf_abytes    (_fun -> _size))
(define-na crypto_aead_xchacha20poly1305_ietf_messagebytes_max (_fun -> _size))

(define-na crypto_aead_xchacha20poly1305_ietf_encrypt_detached
  _aead_encrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_xchacha20poly1305_ietf_decrypt_detached
  _aead_decrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_xchacha20poly1305_ietf_keygen
  ;; takes crypto_aead_xchacha20poly1305_ietf_KEYBYTES bytes
  (_fun _bytes -> _void))

(define xchacha20poly1305_ietf-record
  (and crypto_aead_xchacha20poly1305_ietf_encrypt_detached
       crypto_aead_xchacha20poly1305_ietf_decrypt_detached
       (aeadcipher '(xchacha20-poly1305 stream)
                   crypto_aead_xchacha20poly1305_ietf_KEYBYTES
                   crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
                   crypto_aead_xchacha20poly1305_ietf_ABYTES
                   crypto_aead_xchacha20poly1305_ietf_encrypt_detached
                   crypto_aead_xchacha20poly1305_ietf_decrypt_detached)))

;; ----------------------------------------
;; aes256-gcm

(define crypto_aead_aes256gcm_KEYBYTES   32)
(define crypto_aead_aes256gcm_NSECBYTES   0)
(define crypto_aead_aes256gcm_NPUBBYTES  12)
(define crypto_aead_aes256gcm_ABYTES     16)

(define-na crypto_aead_aes256gcm_is_available (_fun -> _int))
(define-na crypto_aead_aes256gcm_keybytes  (_fun -> _size))
(define-na crypto_aead_aes256gcm_nsecbytes (_fun -> _size))
(define-na crypto_aead_aes256gcm_npubbytes (_fun -> _size))
(define-na crypto_aead_aes256gcm_abytes (_fun -> _size))
(define-na crypto_aead_aes256gcm_messagebytes_max (_fun -> _size))

(define-na crypto_aead_aes256gcm_encrypt_detached
  _aead_encrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_aes256gcm_decrypt_detached
  _aead_decrypt_detached_func #:fail (lambda () #f))

(define-na crypto_aead_aes256gcm_keygen
  ;;takes crypto_aead_aes256gcm_KEYBYTES bytes
  (_fun _bytes -> _void))

(define aes256gcm-record
  (and crypto_aead_aes256gcm_encrypt_detached
       crypto_aead_aes256gcm_decrypt_detached
       (aeadcipher '(aes gcm)
                   crypto_aead_aes256gcm_KEYBYTES
                   crypto_aead_aes256gcm_NPUBBYTES
                   crypto_aead_aes256gcm_ABYTES
                   crypto_aead_aes256gcm_encrypt_detached
                   crypto_aead_aes256gcm_decrypt_detached)))

;; ----------------------------------------

(define cipher-records
  (filter values
          (list chacha20poly1305_ietf-record
                chacha20poly1305-record
                xchacha20poly1305_ietf-record
                aes256gcm-record)))

;; ============================================================
