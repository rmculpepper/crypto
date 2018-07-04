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
         "../common/digest.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define libcrypto-digest-impl%
  (class digest-impl%
    (init-field md) ;; EVP_MD
    (super-new)
    (inherit get-spec get-size get-block-size sanity-check)

    (sanity-check #:size (EVP_MD_size md) #:block-size (EVP_MD_block_size md))

    (define/override (key-size-ok? size) #f)

    (define/override (-new-ctx key)
      (define ctx (EVP_MD_CTX_create))
      (EVP_DigestInit_ex ctx md)
      (new libcrypto-digest-ctx% (impl this) (ctx ctx)))

    (define/override (new-hmac-ctx key)
      (define ctx (HMAC_CTX_new))
      (HMAC_Init_ex ctx key (bytes-length key) md)
      (new libcrypto-hmac-ctx% (impl this) (ctx ctx)))

    (define/override (-digest-buffer buf start end)
      (define outbuf (make-bytes (get-size)))
      (EVP_Digest (ptr-add buf start) (- end start) outbuf md)
      outbuf)

    (define/override (-hmac-buffer key buf start end)
      (define outbuf (make-bytes (get-size)))
      (HMAC md key (bytes-length key) (ptr-add buf start) (- end start) outbuf)
      outbuf)
    ))

(define libcrypto-digest-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (EVP_DigestUpdate ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (EVP_DigestFinal_ex ctx buf)
      (EVP_DigestInit_ex ctx (get-field md impl)))

    (define/override (-copy)
      (let ([other (send impl new-ctx #f)])
        (EVP_MD_CTX_copy_ex (get-field ctx other) ctx)
        other))
    ))

(define libcrypto-hmac-ctx%
  (class digest-ctx%
    (init-field ctx)
    (inherit-field impl)
    (super-new)

    (define/override (-update buf start end)
      (HMAC_Update ctx (ptr-add buf start) (- end start)))

    (define/override (-final! buf)
      (HMAC_Final ctx buf)
      (HMAC_Init_ex ctx #f 0 (get-field md impl)))

    (define/override (-copy)
      (let ([ctx2 (HMAC_CTX_new)])
        (HMAC_CTX_copy ctx2 ctx)
        (new libcrypto-hmac-ctx% (impl impl) (ctx ctx2))))
    ))
