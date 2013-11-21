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
(require racket/class
         (only-in racket/contract/base or/c)
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         (only-in "../common/common.rkt" shrink-bytes))
(provide (all-defined-out))

#|
Key Agreement

 - generate shared params => key-agree-params<%>
 - generate private key-part => key-agree-private-key<%>
 - compute shared secret from private key-part and public key-part (?) => bytes
   - Note: result is biased, not uniform, so unsuitable as key!
   - RFC 2631 calls this ZZ
 - compute key from shared secret
   - eg, use digest (see RFC 2631)

RFC 2631
 - Values: ZZ (shared secret), KEK (key-encryption key), CEK (content-encryption key)
 - ZZ = (dh-compute-secret ....)
 - KM = H (ZZ || other-material)
 - ....

References:
 - [1] http://wiki.openssl.org/index.php/EVP_Key_Agreement
 - [2] http://wiki.openssl.org/index.php/Diffie_Hellman
 - [3] PKCS #3
 - [4] https://tools.ietf.org/html/rfc2631
 - [5] http://www.openssl.org/docs/crypto/dh.html
 - [6] http://www.cryptopp.com/wiki/Diffie-Hellman

[2] claims/implies that i2d_DHparams_bio includes the public key in
its output. I'm skeptical, because id2_DHparams produces the same
output before and after DH_generate_key, and the docs say it writes a
PKCS#3 DHparameter, which does not include a public key
component (says [3]). So I'm not sure of the "right" way(s) to format
a DH public key w/ params.

TODO: check params (eg safe primes) on generate-params OR read-params

TODO: support predefined DH params
 - http://tools.ietf.org/html/rfc3526
 - http://tools.ietf.org/html/rfc5114

|#

(define key-agree-impl<%>
  (interface ()
    generate-params  ;; sym ParamgenSpec -> key-agree-params<%>
    read-params      ;; sym bytes -> key-agree-params<%>
    ;; read-params+key  ;; sym (list bytes^3) -> key-agree-key<%>
    ))

(define key-agree-params<%>
  (interface ()
    generate-key     ;; sym KeygenSpec -> key-agree-key<%>
    read-key         ;; sym (list bytes^2) -> key-agree-key<%>
    write-params     ;; sym KeyFormat -> bytes
    ))

(define key-agree-key<%>
  (interface ()
    get-params       ;; -> key-agree-params<%>
    write-key        ;; sym KeyFormat -> (list bytes^3)
    compute-secret   ;; sym bytes -> bytes
    ))

(define allowed-dh-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (generator ,(or/c 2 5) "(or/c 2 5)")))

(define libcrypto-dh-impl%
  (class* impl-base% (key-agree-impl<%>)
    (super-new (spec 'dh))

    (define/public (generate-params who config)
      (check-keygen-spec who config allowed-dh-paramgen)
      (let ([nbits (keygen-spec-ref config 'nbits)]
            [generator (or (keygen-spec-ref config 'generator) 2)])
        (define dh (DH_new))
        (DH_generate_parameters_ex dh nbits generator)
        ;; FIXME: DH_check ???

        (eprintf "dh->privkey = ~e\n" (DH_st_prefix-privkey dh))
        (eprintf "dh->pubkey = ~e\n" (DH_st_prefix-pubkey dh))

        (new libcrypto-dh-params% (impl this) (dh dh))))

    (define/public (read-params who buf fmt)
      (unless (eq? fmt #f)
        (error who "bad DH parameters format\n  format: ~e" fmt))
      (define dh (d2i_DHparams buf (bytes-length buf)))
      ;; FIXME: DH_check
      (new libcrypto-dh-params% (impl this) (dh dh)))

    (define/public (read-params+key who bufs fmt)
      (unless (eq? fmt #f)
        (error who "bad DH parameters and key format\n  format: ~e" fmt))
      (define params (read-params who (car bufs) fmt))
      (send params read-key who (cdr bufs) fmt))
    ))

(define allowed-dh-keygen '())

(define libcrypto-dh-params%
  (class* ctx-base% (key-agree-params<%>)
    (init-field dh)
    (inherit-field impl)
    (super-new)

    (define/public (generate-key who config)
      (check-keygen-spec 'dh-keygen config allowed-dh-keygen)
      (define kdh (DHparams_dup dh))
      (DH_generate_key kdh)
      (new libcrypto-dh-key% (impl impl) (dh kdh) (params this)))

    (define/public (read-key who bufs fmt)
      (unless (eq? fmt #f)
        (error who "bad DH key format\n  format: ~e" fmt))
      (define kdh (DHparams_dup dh))
      (define pubkey (BN_bin2bn (car bufs)))
      (define privkey (BN_bin2bn (cadr bufs)))
      (when (or (DH_st_prefix-pubkey kdh) (DH_st_prefix-privkey kdh))
        (error who "internal error; keys found in DH parameters object"))
      (set-DH_st_prefix-pubkey! kdh pubkey)
      (set-DH_st_prefix-privkey! kdh privkey)
      (BN-no-gc pubkey)
      (BN-no-gc privkey)
      (new libcrypto-dh-key% (impl impl) (dh kdh) (params this)))

    (define/public (write-params who fmt)
      (unless (eq? fmt #f)
        (error who "bad DH parameters format\n  format: ~e" fmt))
      (define len (i2d_DHparams dh #f))
      (define buf (make-bytes len))
      (define len2 (i2d_DHparams dh buf))
      (shrink-bytes buf len2))
    ))

(define libcrypto-dh-key%
  (class* ctx-base% (key-agree-key<%>)
    (init-field dh [params #f])
    (inherit-field impl)
    (super-new)

    (define/public (get-params who)
      (unless params
        (define dhp (DHparams_dup dh))
        (set! params (new libcrypto-dh-params% (impl impl) (dh dhp))))
      params)

    (define/public (write-key who fmt)
      (unless (eq? fmt #f)
        (error who "bad DH key format\n  format: ~e" fmt))
      (define pubkey (DH_st_prefix-pubkey dh))
      (define privkey (DH_st_prefix-privkey dh))
      (list (send (get-params who) write-params who fmt)
            (BN->bytes/bin pubkey)
            (BN->bytes/bin privkey)))

    (define/public (compute-secret peer-pubkey)
      (define pub-bn (BN_bin2bn peer-pubkey))
      (DH_compute_key dh pub-bn))

    ))
