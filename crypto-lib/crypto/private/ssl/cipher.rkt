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
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "macros.rkt"
         "rand.rkt"
         "util.rkt"
         (for-syntax racket/base
                     racket/syntax))
(provide (all-defined-out))

(define cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field ciphers ;; non-empty list of EVP_CIPHER
                spec)  ;; CipherSpec
    (define-values (block-size key-size iv-size) (get-sizes (car ciphers)))
    (for ([cipher (in-list (cdr ciphers))])
      (let-values ([(b k iv) (get-sizes cipher)])
        (unless (and (= b block-size) (equal? iv iv-size))
          (error 'libcrypto-cipher-impl%
                 "inconsistent cipher block or IV sizes\n  cipher: ~e" spec))))
    (super-new)

    (define/private (get-sizes cipher)
      (match (ptr-ref cipher (_list-struct _int _int _int _int))
        [(list _ size keylen ivlen)
         (values size keylen (and (> ivlen 0) ivlen))]))

    (define/public (get-name) spec)
    (define/public (get-key-size) key-size)
    (define/public (get-block-size) block-size)
    (define/public (get-iv-size) iv-size)

    (define cipher 'bad-fixme)

    (define/public (new-ctx who key iv enc? pad?)
      (unless (and (bytes? key) (>= (bytes-length key) key-size))
        (error who "bad key: ~e" key))
      (when iv-size
        (unless (and (bytes? iv) (>= (bytes-length iv) iv-size))
          (error who "bad iv: ~e" iv)))
      (let ([ctx (EVP_CIPHER_CTX_new)])
        (EVP_CipherInit_ex ctx cipher key (and iv-size iv) enc?)
        (EVP_CIPHER_CTX_set_padding ctx pad?)
        (new cipher-ctx% (impl this) (ctx ctx) (encrypt? enc?))))

    (define/public (generate-key)
      (random-bytes key-size))
    (define/public (generate-iv)
      ;; FIXME: ok to use use pseudo-random-bytes?
      (and iv-size (random-bytes iv-size)))
    ))

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
