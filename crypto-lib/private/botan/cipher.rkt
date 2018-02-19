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
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "../common/ufp.rkt"
         "ffi.rkt")
(provide botan2-cipher-impl%)

(define botan2-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field bname) ;; String, like "AES-128/GCM"
    (inherit-field info)
    (inherit sanity-check about get-iv-size)
    (super-new)

    (let ()
      (define ctx (botan_cipher_init bname 0))
      (when (zero? (botan_cipher_valid_nonce_length ctx (get-iv-size)))
        (eprintf "iv size ~s not ok; cipher: ~a\n" (get-iv-size) (about)))
      #;
      (sanity-check #:iv-size (botan_cipher_get_default_nonce_length ctx)
                    #| #:chunk-size (botan_cipher_get_update_granularity ctx) |#))

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (define ctx (botan_cipher_init bname (if enc? FLAG_ENCRYPT FLAG_DECRYPT)))
      (botan_cipher_set_key ctx key (bytes-length key))
      (botan_cipher_start ctx iv (bytes-length iv))
      (new botan2-cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?)
           (auth-len auth-len) (attached-tag? attached-tag?)))
    ))

(define botan2-cipher-ctx%
  (class cipher-ctx%
    (init-field ctx)
    (super-new (pad? #f))
    (inherit-field impl encrypt? auth-len)
    (inherit about)
    (field [aad-buffer (open-output-bytes)])

    (define/public (get-spec) (send impl get-spec))

    (define/override (-close)
      (when aad-buffer (set! aad-buffer #f)))

    (define/override (-do-aad inbuf instart inend)
      (write-bytes inbuf aad-buffer instart inend))

    (define/private (check/flush-aad-buffer)
      (when aad-buffer
        (define aad (get-output-bytes aad-buffer #t))
        (botan_cipher_set_associated_data ctx aad (bytes-length aad))
        (set! aad-buffer #f)))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      (check/flush-aad-buffer)
      (define-values (r outwrote inread)
        (botan_cipher_update ctx (if final? FLAG_FINAL 0) outbuf (bytes-length outbuf)
                             (ptr-add inbuf instart) (- inend instart)))
      (unless (zero? r)
        (eprintf "r = ~s\n" r))
      (unless (= inread (- inend instart))
        (internal-error "input not completely processed: ~s of ~s\n  cipher: ~a"
                        inread (- inend instart) (about)))
      outwrote)

    (define/override (-do-encrypt-end auth-len)
      (check/flush-aad-buffer)
      (define outbuf (make-bytes auth-len))
      (define-values (r outwrote inread)
        (botan_cipher_update ctx FLAG_FINAL outbuf auth-len #"" 0))
      (unless (= outwrote auth-len)
        (internal-error "did not get auth tag, outwrote = ~s\n  cipher: ~a"
                        outwrote (about)))
      outbuf)

    (define/override (-do-decrypt-end auth-tag)
      (check/flush-aad-buffer)
      (define-values (r outwrote inread)
        (botan_cipher_update ctx FLAG_FINAL #f 0 auth-tag (bytes-length auth-tag)))
      (unless (= inread (bytes-length auth-tag))
        (internal-error "did not process auth tag, inread = ~s\n  cipher: ~a"
                        inread (about))))
    ))
