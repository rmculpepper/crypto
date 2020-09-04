;; Copyright 2020 Ryan Culpepper
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
         racket/contract
         "../main.rkt"
         "../private/sodium/pkey.rkt"
         "../private/sodium/ffi.rkt")

(provide (contract-out
          [crypto-box-seal
           (-> (and/c pk-key? (is-a?/c sodium-x25519-key%)) bytes?
               bytes?)]
          [crypto-box-seal-open
           (-> (and/c private-key? (is-a?/c sodium-x25519-key%)) bytes?
               bytes?)]
          [crypto-secretbox
           (-> bytes? bytes? bytes?
               (values bytes? bytes?))]
          [crypto-secretbox-open
           (-> bytes? bytes? bytes? bytes?
               bytes?)]))

(define (crypto-box-seal to-pk msg)
  (send to-pk crypto-box-seal msg))

(define (crypto-box-seal-open to-sk ctext)
  (send to-sk crypto-box-seal-open ctext))

(define (crypto-secretbox key nonce msg)
  (define ctext+auth
    (or (crypto_secretbox_detached msg nonce key)
        (error 'crypto-secretbox "failed")))
  (values (car ctext+auth) (cadr ctext+auth)))

(define (crypto-secretbox-open key nonce ctext auth)
  (or (crypto_secretbox_open_detached ctext auth nonce key)
      (error 'crypto-secretbox-open "authenticated decryption failed")))

;; TODO: secretbox as cipher?
;; (sodium-secretbox-cipher) -> cipher-impl?

;; TODO: ed25519 key -> curve25519 key
;; (send ed-key to-curve25519) -> pk-key (ecx, using curve25519)

