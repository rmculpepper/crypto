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
         "../common/cipher.rkt"
         "../common/error.rkt"
         "../common/ufp.rkt"
         "ffi.rkt")
(provide sodium-cipher-impl%)

(define sodium-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field cipher)
    (inherit-field info)
    (inherit sanity-check)
    (super-new)

    (sanity-check #:iv-size (aeadcipher-noncesize cipher))

    (define/override (get-key-size) (aeadcipher-keysize cipher))
    (define/override (get-key-sizes) (list (aeadcipher-keysize cipher)))
    (define/override (get-iv-size) (aeadcipher-noncesize cipher))
    (define/override (get-auth-size) (aeadcipher-authsize cipher))
    (define/override (get-chunk-size) 1)

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (new sodium-cipher-ctx% (impl this) (cipher cipher) (encrypt? enc?) (key key) (iv iv)
           (auth-len auth-len) (attached-tag? attached-tag?)))
    ))

(define sodium-cipher-ctx%
  (class cipher-ctx%
    (init-field cipher key iv)
    (super-new (pad? #f))
    (inherit-field impl encrypt? auth-len)
    (field [aad-buffer (open-output-bytes)]
           [msg-buffer (open-output-bytes)])

    (define/public (get-spec) (send impl get-spec))

    (define/override (-close)
      (when key (set! key #f))
      (when iv  (set! iv #f))
      (when aad-buffer (set! aad-buffer #f))
      (when msg-buffer (set! msg-buffer #f)))

    (define/override (-do-aad inbuf instart inend)
      (write-bytes inbuf aad-buffer instart inend))

    ;; -make-crypt-ufp : Boolean UFP -> UFP[Bytes,#f/AuthTag => AuthTag/#f]
    (define/override (-make-crypt-ufp enc? next)
      (define (update inbuf instart inend)
        (-do-crypt inbuf instart inend))
      (define (finish partial auth-tag)
        (-do-crypt partial 0 (bytes-length partial))
        (define aad (get-output-bytes aad-buffer #t))
        (define msg (get-output-bytes msg-buffer #t))
        (define outbuf (make-bytes (bytes-length msg)))
        (cond [enc?
               (define authbuf (make-bytes auth-len))
               (define authlen ((aeadcipher-encrypt cipher) outbuf authbuf msg aad iv key))
               (unless authlen (crypto-error "encryption failed"))
               (send next update outbuf 0 (bytes-length outbuf))
               (send next finish (subbytes authbuf 0 authlen))]
              [else
               (define s ((aeadcipher-decrypt cipher) outbuf msg auth-tag aad iv key))
               (unless (zero? s) (crypto-error "authenticated decryption failed"))
               (send next update outbuf 0 (bytes-length outbuf))
               (send next finish #f)]))
      (sink-ufp update finish))

    (define/override (-do-crypt inbuf instart inend)
      (write-bytes inbuf msg-buffer instart inend))
    (define/override (-do-encrypt-end auth-len) (err/no-impl))
    (define/override (-do-decrypt-end auth-tag) (err/no-impl))
    ))
