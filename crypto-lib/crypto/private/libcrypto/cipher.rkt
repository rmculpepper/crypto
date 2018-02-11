;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define libcrypto-cipher-impl%
  (class* cipher-impl-base% (cipher-impl<%>)
    (init-field cipher) ;; EVP_CIPHER
    (inherit-field info)
    (inherit get-spec get-mode sanity-check get-auth-size uses-padding?)
    (super-new)
    (define-values (block-size key-size iv-size)
      (match (ptr-ref cipher (_list-struct _int _int _int _int))
        [(list _ size keylen ivlen)
         (values size keylen ivlen)]))
    (sanity-check #:block-size block-size
                  #:iv-size iv-size)

    (define/override (get-block-size) block-size)
    (define/override (get-iv-size) iv-size)
    (define/override (get-chunk-size) block-size) ;; FIXME???

    (define/override (-new-ctx key iv enc? pad? auth-len attached-tag?)
      (let ([ctx (EVP_CIPHER_CTX_new)])
        (EVP_CipherInit_ex ctx cipher #f #f enc?)
        (EVP_CIPHER_CTX_set_key_length ctx (bytes-length key))
        ;; Set auth-len (OCB mode only; other modes don't need)
        ;; https://www.openssl.org/docs/manmaster/man3/EVP_EncryptInit.html
        (case (get-mode)
          [(ocb) (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_TAG auth-len #f)]
          [else (void)])
        (when (and auth-len (not (equal? auth-len (get-auth-size))))
          ;; In OpenSSL 1.0.2g, setting taglen (with null tag) segfaults.
          ;; FIXME: guard with version check => racket error
          (define (set-len) (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_TAG auth-len #f))
          (case (get-mode)
            [(gcm) (when (not enc?) (set-len))]
            [(ocb) (set-len)]))
        ;; Set ivlen
        (case (get-mode)
          [(gcm ocb) (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_IVLEN (bytes-length iv) #f)]
          [else (void)])
        (EVP_CipherInit_ex ctx cipher key iv enc?)
        ;; Disable libcrypto padding; cipher-ctx% handles automatically (FIXME?)
        (EVP_CIPHER_CTX_set_padding ctx #f)
        (new libcrypto-cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?) (pad? pad?)
             (auth-len auth-len) (attached-tag? attached-tag?))))
    ))

;; Since 1.0.1d okay to set tag right before DecryptFinal
;; - https://github.com/openssl/openssl/blob/master/demos/evp/aesgcm.c
;; - https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption

(define libcrypto-cipher-ctx%
  (class cipher-ctx%
    (init-field ctx)
    (super-new)
    (inherit-field impl)
    (inherit get-block-size get-chunk-size)

    (define/public (get-mode) (send impl get-mode))

    (define/override (-do-aad inbuf instart inend)
      (EVP_CipherUpdate ctx #f (ptr-add inbuf instart) (- inend instart)))

    (define/override (-do-crypt enc? final? inbuf instart inend outbuf)
      (EVP_CipherUpdate ctx outbuf (ptr-add inbuf instart) (- inend instart)))

    (define/override (-do-encrypt-end auth-len)
      (define outbuf (make-bytes (get-chunk-size))) ;; to be safe?
      (define len (or (EVP_CipherFinal_ex ctx outbuf)
                      (err/crypt-failed #t (send impl aead?))))
      (unless (zero? len) (internal-error "EVP_CipherFinal_ex output len = ~s" len))
      (case (get-mode)
        [(gcm ocb) (-get-auth-tag auth-len)]
        [else #""]))

    (define/override (-do-decrypt-end auth-tag)
      (case (get-mode)
        [(gcm ocb) (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_SET_TAG (bytes-length auth-tag) auth-tag)]
        [else (void)])
      (define outbuf (make-bytes (get-chunk-size))) ;; to be safe?
      (define len (or (EVP_CipherFinal_ex ctx outbuf)
                      (err/crypt-failed #f (send impl aead?))))
      (unless (zero? len) (internal-error "EVP_CipherFinal_ex output len = ~s" len)))

    (define/private (-get-auth-tag taglen)
      (define tagbuf (make-bytes taglen))
      (EVP_CIPHER_CTX_ctrl ctx EVP_CTRL_AEAD_GET_TAG taglen tagbuf)
      tagbuf)

    (define/override (-close)
      (when ctx
        (EVP_CIPHER_CTX_free ctx)
        (set! ctx #f)))
    ))
