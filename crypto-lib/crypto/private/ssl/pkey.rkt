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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/error.rkt"
         "ffi.rkt"
         "macros.rkt"
         "util.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide (all-defined-out))

(define pkey-impl%
  (class* object% (pkey-impl<%>)
    (init-field name
                pktype
                keygen
                ok-digests
                encrypt-ok?)
    (super-new)

    (define/public (get-name) name)

    (define/public (read-key who public? buf start end)
      (check-input-range who buf start end)
      (let* ([d2i (if public? d2i_PublicKey d2i_PrivateKey)]
             [evp (d2i pktype (ptr-add buf start) (- end start))])
        (new pkey-ctx% (impl this) (evp evp) (private? (not public?)))))

    (define/public (generate-key args)
      (apply keygen args))

    (define/public (digest-ok? di)
      (or (eq? ok-digests 'all)
          (and (memq (send di get-name) ok-digests) #t)))
    (define/public (can-encrypt?)
      encrypt-ok?)
    ))

(define pkey-ctx%
  (class* base-ctx% (pkey-ctx<%>)
    (init-field evp
                private?)
    (super-new)

    (define/public (is-private?) private?)

    (define/public (get-max-signature-size) (EVP_PKEY_size evp))
    (define/public (get-key-size/bits) (EVP_PKEY_bits evp))

    (define/public (write-key who public?)
      (let* ([i2d (if public? i2d_PublicKey i2d_PrivateKey)]
             [i2d-length (if public? i2d_PublicKey-length i2d_PrivateKey-length)]
             [buf (make-bytes (i2d-length evp))])
        (i2d evp buf)
        buf))

    (define/public (equal-to-key? other)
      (and (is-a? other pkey-ctx%)
           (EVP_PKEY_cmp evp (get-field evp other))))

    ;; From headers, EVP_{Sign,Verify}{Init_ex,Update} are just macros for
    ;; EVP_Digest{Init_ex,Update}. So digest state is compatible.

    (define/public (sign! who digest-ctx buf start end)
      (unless private?
        (error who "not a private key"))
      ;; FIXME: add method to digest-ctx% instead (?)
      (unless (is-a? digest-ctx digest-ctx%)
        (eprintf "args = ~s\n" (list who digest-ctx buf start end))
        (error who "invalid digest context, not compatible with libcrypto: ~e" digest-ctx))
      (check-output-range who buf start end (get-max-signature-size))
      (let ([dctx (get-field ctx digest-ctx)])
        (unless dctx (error who "digest context is closed"))
        (EVP_SignFinal dctx (ptr-add buf start) evp)))

    (define/public (verify who digest-ctx buf start end)
      ;; FIXME: add methdo to digest-ctx% instead (?)
      (unless (is-a? digest-ctx digest-ctx%)
        (error who "invalid digest context, not compatible with libcrypto"))
      (check-input-range who buf start end)
      (let ([dctx (get-field ctx digest-ctx)])
        (unless dctx (error who "digest context is closed"))
        (EVP_VerifyFinal dctx (ptr-add buf start) (- end start) evp)))

    (define/public (encrypt/decrypt who encrypt? public? inbuf instart inend)
      (unless (or public? (is-private?))
        (error who "not a private key"))
      (check-input-range who inbuf instart inend)
      (let* ([outbuf (make-bytes (get-max-signature-size))]
             [e/d (if encrypt? EVP_PKEY_encrypt EVP_PKEY_decrypt)]
             [outlen (e/d outbuf (ptr-add inbuf instart) (- inend instart) evp)])
        (shrink-bytes outbuf outlen)))

    ))
