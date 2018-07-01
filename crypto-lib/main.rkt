;; Copyright 2012-2018 Ryan Culpepper
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
(require racket/contract/base
         "private/common/interfaces.rkt"
         "private/common/catalog.rkt"
         "private/common/factory.rkt"
         "private/common/digest.rkt"
         "private/common/cipher.rkt"
         "private/common/pkey.rkt"
         "private/common/kdf.rkt"
         "private/common/util.rkt")

(provide crypto-factory?
         digest-spec?
         digest-impl?
         digest-ctx?
         cipher-spec?
         cipher-impl?
         cipher-ctx?
         pk-spec?
         pk-impl?
         pk-parameters?
         pk-key?
         kdf-spec?
         kdf-impl?
         (struct-out bytes-range)
         input/c

         ;; factory
         (recontract-out
          crypto-factories
          get-factory
          factory-version
          factory-print-info
          get-digest
          get-cipher
          get-pk
          get-kdf)

         ;; digest
         (recontract-out
          digest-size
          digest-block-size
          digest
          hmac
          make-digest-ctx
          digest-update
          digest-final
          digest-copy
          digest-peek-final
          make-hmac-ctx
          generate-hmac-key)

         ;; cipher
         (recontract-out
          cipher-default-key-size
          cipher-key-sizes
          cipher-block-size
          cipher-iv-size
          cipher-aead?
          cipher-default-auth-size
          cipher-chunk-size
          make-encrypt-ctx
          make-decrypt-ctx
          encrypt-ctx?
          decrypt-ctx?
          cipher-update
          cipher-update-aad
          cipher-final
          cipher-get-auth-tag
          encrypt
          decrypt
          encrypt/auth
          decrypt/auth
          generate-cipher-key
          generate-cipher-iv)

         ;; pkey
         private-key?
         public-only-key?
         (recontract-out
          pk-can-sign?
          pk-can-encrypt?
          pk-can-key-agree?
          pk-has-parameters?
          pk-key->parameters
          public-key=?
          pk-key->public-only-key
          pk-key->datum
          datum->pk-key
          pk-parameters->datum
          datum->pk-parameters
          pk-sign
          pk-verify
          pk-sign-digest
          pk-verify-digest
          digest/sign
          digest/verify
          pk-encrypt
          pk-decrypt
          pk-derive-secret
          generate-pk-parameters
          generate-private-key)

         ;; kdf
         (recontract-out
          kdf
          pwhash
          pwhash-verify
          pbkdf2-hmac
          scrypt)

         ;; util
         (recontract-out
          hex->bytes
          bytes->hex
          bytes->hex-string
          crypto-bytes=?))
