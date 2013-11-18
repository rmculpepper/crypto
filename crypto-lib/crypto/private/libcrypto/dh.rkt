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
         "ffi.rkt"
         "macros.rkt"
         "util.rkt"
         (only-in "../common/common.rkt" shrink-bytes)
         (only-in net/base64 base64-decode)
         (only-in racket/list last)
         (for-syntax racket/base
                     racket/syntax))

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
 - Parties: ZZ (shared secret), KEK (key-encryption key), CEK (content-encryption key)
 - ZZ = (dh-compute-secret ....)
 - KM = H (ZZ || other-material)
 - ....

References:
 - http://wiki.openssl.org/index.php/EVP_Key_Agreement
 - https://tools.ietf.org/html/rfc2631

|#

(define allowed-dh-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?")
    (generator ,(or/c 2 5) "(or/c 2 5)")))

(define (dh-paramgen config)
  (check-keygen-spec 'dh-paramgen config allowed-dh-paramgen)
  (let ([nbits (keygen-spec-ref config 'nbits)]
        [generator (or (keygen-spec-ref config 'generator) 2)])
    (define dh (DH_new))
    (DH_generate_parameters_ex dh nbits generator)
    (new libcrypto-dh-params% (dh dh))))

(define allowed-dh-keygen '())

(define (dh-keygen dhp config)
  (check-keygen-spec 'dh-keygen config allowed-dh-keygen)
  (define dh (DHparams_dup dhp))
  (DH_generate_key dh)
  (new libcrypto-dh-key% (dh dh)))

(define (dh-compute-secret dh peer-pubkey)
  (define pub-bn (BN_new))
  (define pub-bn (BN_dec2bn (number->string peer-pubkey))) ;; or whatever
  (DH_compute_key dh pub-bn))

(define (key-digest who size-bytes)
  (cond [(<= size-bytes 16) 'sha256]
        [(<= size-bytes 32) 'sha512]
        [else
         (error who "cannot get key digest with requested size\n  key size: ~s bytes" size-bytes)]))




(define (dh-compute-key dh peer-pubkey [size-bytes 16]
                        #:digest [di (key-digest 'dh-compute-key size-bytes)])
  (define secret (dh-compute-secret dh peer-pubkey))
  (define secret*
    (cond [(eq? di #f) secret]
          [else (digest di secret)]))
  (shrink-bytes secret* 0 size-bytes))

;; ============================================================

(define (bn-size bn)
  (ceiling (/ (BN_num_bits bn) 8)))

(define (bn->bytes bn)
  (let ([bs (make-bytes (bn-size bn))])
    (shrink-bytes bs (BN_bn2bin bn bs))))

(define (bytes->bn bs)
  (BN_bin2bn bs))

;; ------------------------------------------------------------

(define-struct !dh (bits bs))
(define-struct dhkey (p))

;; DH: struct dh_st {pad version p g length pub_key ...}
(define (dhkey-pubk dh)
  (bn->bytes
   (last 
    (ptr-ref (dhkey-p dh) 
             (_list-struct _int _int _BIGNUM _BIGNUM _long _BIGNUM)))))

(define (params->dhkey params)
  (let* ([bs (!dh-bs params)]
         [dhp (d2i_DHparams bs (bytes-length bs))])
    (make-dhkey dhp)))

(define (dhkey-size dh)
  (DH_size (dhkey-p dh)))

(define (generate-dhkey params)
  (let ([dh (params->dhkey params)])
    (DH_generate_key (dhkey-p dh))
    (values dh (dhkey-pubk dh))))

(define (compute-key dh pubk)
  (let* ([bs (make-bytes (dhkey-size dh))]
         [bn (bytes->bn pubk)])
    (DH_compute_key bs bn (dhkey-p dh))
    (BN_free bn)
    bs))

(define-syntax (define-dh stx)
  (syntax-case stx ()
    [(_ bits bbs)
     (with-syntax ([params (format-id stx "dh:~a" (syntax-e #'bits))])
       #'(begin
           (define params (make-!dh bits (base64-decode bbs)))
           (put-symbols! dh.symbols params)))]))

(define-symbols dh.symbols
  !dh? dhkey? (!dh-bits dh-bits) dhkey-size compute-key)

;; DH parameter generation can take a really long time
;; These are base64 encoded defaults provided by the OpenSSL project.
;; openssl dhparam can be used to generate new ones
(define-dh 192
  #"MB4CGQDUoLoCULb9LsYm5+/WN992xxbiLQlEuIsCAQM=")
(define-dh 512
  #"MEYCQQDaWDwW2YUiidDkr3VvTMqS3UvlM7gE+w/tlO+cikQD7VdGUNNpmdsp13Yn
    a6LT1BLiGPTdHghM9tgAPnxHdOgzAgEC")
(define-dh 1024
  #"MIGHAoGBAJf2QmHKtQXdKCjhPx1ottPb0PMTBH9A6FbaWMsTuKG/K3g6TG1Z1fkq
    /Gz/PWk/eLI9TzFgqVAuPvr3q14a1aZeVUMTgo2oO5/y2UHe6VaJ+trqCTat3xlx
    /mNbIK9HA2RgPC3gWfVLZQrY+gz3ASHHR5nXWHEyvpuZm7m3h+irAgEC")
(define-dh 2048
  #"MIIBCAKCAQEA7ZKJNYJFVcs7+6J2WmkEYb8h86tT0s0h2v94GRFS8Q7B4lW9aG9o
    AFO5Imov5Jo0H2XMWTKKvbHbSe3fpxJmw/0hBHAY8H/W91hRGXKCeyKpNBgdL8sh
    z22SrkO2qCnHJ6PLAMXy5fsKpFmFor2tRfCzrfnggTXu2YOzzK7q62bmqVdmufEo
    pT8igNcLpvZxk5uBDvhakObMym9mX3rAEBoe8PwttggMYiiw7NuJKO4MqD1llGkW
    aVM8U2ATsCun1IKHrRxynkE1/MJ86VHeYYX8GZt2YA8z+GuzylIOKcMH6JAWzMwA
    Gbatw6QwizOhr9iMjZ0B26TE3X8LvW84wwIBAg==")
(define-dh 4096
  #"MIICCAKCAgEA/urRnb6vkPYc/KEGXWnbCIOaKitq7ySIq9dTH7s+Ri59zs77zty7
    vfVlSe6VFTBWgYjD2XKUFmtqq6CqXMhVX5ElUDoYDpAyTH85xqNFLzFC7nKrff/H
    TFKNttp22cZE9V0IPpzedPfnQkE7aUdmF9JnDyv21Z/818O93u1B4r0szdnmEvEF
    bKuIxEHX+bp0ZR7RqE1AeifXGJX3d6tsd2PMAObxwwsv55RGkn50vHO4QxtTARr1
    rRUV5j3B3oPMgC7Offxx+98Xn45B1/G0Prp11anDsR1PGwtaCYipqsvMwQUSJtyE
    EOQWk+yFkeMe4vWv367eEi0Sd/wnC+TSXBE3pYvpYerJ8n1MceI5GQTdarJ77OW9
    bGTHmxRsLSCM1jpLdPja5jjb4siAa6EHc4qN9c/iFKS3PQPJEnX7pXKBRs5f7AF3
    W3RIGt+G9IVNZfXaS7Z/iCpgzgvKCs0VeqN38QsJGtC1aIkwOeyjPNy2G6jJ4yqH
    ovXYt/0mc00vCWeSNS1wren0pR2EiLxX0ypjjgsU1mk/Z3b/+zVf7fZSIB+nDLjb
    NPtUlJCVGnAeBK1J1nG3TQicqowOXoM6ISkdaXj5GPJdXHab2+S7cqhKGv5qC7rR
    jT6sx7RUr0CNTxzLI7muV2/a4tGmj0PSdXQdsZ7tw7gbXlaWT1+MM2MCAQI=")

(define-provider provide-dh dh.symbols)

(provide-dh)
(provide provide-dh generate-dhkey
         (struct-out !dh)
         (struct-out dhkey))
