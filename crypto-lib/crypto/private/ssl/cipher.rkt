;; Copyright 2012 Ryan Culpepper
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
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field cipher ;; EVP_CIPHER
                spec)
    (define-values (block-size key-size iv-size)
      (match (ptr-ref cipher (_list-struct _int _int _int _int))
        [(list _ size keylen ivlen)
         (values size keylen ivlen)]))
    (let ()
      (define (check what value expected)
        (unless (= value expected)
          (error 'cipher-impl%
                 "internal error: inconsistent ~a\n  cipher: ~e\n  expected: ~e\n  got: ~e"
                 what spec value expected)))
      (check "block size" block-size (cipher-spec-block-size spec))
      (check "IV size" iv-size (cipher-spec-iv-size spec)))
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-block-size) block-size)
    (define/public (get-iv-size) iv-size)

    (define/public (new-ctx who key iv enc? pad?)
      (check-key-size who spec (bytes-length key))
      (unless (= (if (bytes? iv) (bytes-length iv) 0) iv-size)
        (error who
               "bad IV size for cipher\n  cipher: ~e\n  expected: ~s bytes\n  got: ~s bytes"
               spec (if (bytes? iv) (bytes-length iv) 0) iv-size))
      (let ([ctx (EVP_CIPHER_CTX_new)])
        (EVP_CipherInit_ex ctx cipher #f #f enc?)
        (EVP_CIPHER_CTX_set_key_length ctx (bytes-length key))
        (EVP_CIPHER_CTX_set_padding ctx (and pad? (cipher-spec-uses-padding? spec)))
        (EVP_CipherInit_ex ctx cipher key (and iv-size iv) enc?)
        (new cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?))))
    ))

;; Conflicting notes about GCM mode:
;; - Must set AAD with NULL output buffer; MUST set, even if 0-length (use #"")
;;   See http://incog-izick.blogspot.com/2011/08/using-openssl-aes-gcm.html
;; - No, don't, if using EVP_CipherInit_ex
;;   See http://stackoverflow.com/questions/12153009/

(define cipher-ctx%
  (class* base-ctx% (cipher-ctx<%>)
    (init-field ctx
                encrypt?)
    (inherit-field impl)
    (super-new)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      (unless ctx (error who "cipher context is closed"))
      (check-input-range who inbuf instart inend)
      (check-output-range who outbuf outstart outend (maxlen (- inend instart)))
      (EVP_CipherUpdate ctx (ptr-add outbuf outstart)
                        (ptr-add inbuf instart)
                        (- inend instart)))

    (define/public (final! who outbuf outstart outend)
      (unless ctx (error who "cipher context is closed"))
      (check-output-range who outbuf outstart outend (maxlen 0))
      (begin0 (EVP_CipherFinal_ex ctx (ptr-add outbuf outstart))
        (EVP_CIPHER_CTX_free ctx)
        (set! ctx #f)))

    (define/private (maxlen inlen)
      (+ inlen (send impl get-block-size)))
    ))
