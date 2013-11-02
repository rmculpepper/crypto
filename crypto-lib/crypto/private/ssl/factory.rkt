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
         racket/match
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/catalog.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "rand.rkt"
         "ffi.rkt"
         "macros.rkt")
(provide ssl-factory)

#|
To print all digests:

(EVP_MD_do_all_sorted
 (lambda (m from to)
   (if m
       (printf "digest ~s\n" from)
       (printf "alias ~s => ~s\n" from to))))

To print all ciphers:

(EVP_CIPHER_do_all_sorted
 (lambda (c from to)
   (if c
       (printf "cipher ~s\n" from)
       (printf "alias ~s => ~s\n" from to))))
|#

(define libcrypto-digests
  #hasheq(;; DigestSpec -> String
          ;; Maps to name for EVP_get_digestbyname
          [md4       . "md4"]
          [md5       . "md5"]
          [ripemd160 . "ripemd160"]
          [sha0      . "sha"]
          [sha1      . "sha1"]
          [sha224    . "sha224"]
          [sha256    . "sha256"]
          [sha384    . "sha384"]
          [sha512    . "sha512"]))

(define libcrypto-ciphers
  '(;; [CipherName Modes KeySizes String]
    ;; Note: key sizes in bits (to match lookup string); converted to bytes below
    ;; keys=#f means inherit constraints, don't add to string
    [aes (cbc cfb cfb1 cfb8 ctr ecb gcm ofb xts) (128 192 256) "aes"]
    [blowfish (cbc cfb ecb ofb) #f "bf"]
    [camellia (cbc cfb cfb1 cfb8 ecb ofb) (128 192 256) "camellia"]
    [cast128 (cbc cfb ecb ofb) #f "cast5"]
    [des (cbc cfb cfb1 cfb8 ecb ofb) #f "des"]
    [des-ede2 (cbc cfb ofb) #f "des-ede"] ;; ECB mode???
    [des-ede3 (cbc cfb ofb) #f "des-ede3"] ;; ECB mode???
    [rc4 (stream) #f "rc4"]))

;; cross : (U string (listof string)) ... -> (listof string)
(define (cross . parts)
  (let cross* ([parts parts] [rprefix null])
    (cond [(null? parts)
           (list (apply string-append (reverse rprefix)))]
          [(string? (car parts))
           (cross* (cdr parts) (cons (car parts) rprefix))]
          [(list? (car parts))
           (apply append
                  (for/list ([next (in-list (car parts))])
                    (cross* (cdr parts) (cons next rprefix))))])))

;; FIXME: des-ede-ecb, des-ede3-ecb ???
(define libcrypto-cipher-names
  '(aes-128-cbc    aes-128-ecb
    aes-192-cbc    aes-192-ecb
    aes-256-cbc    aes-256-ecb
    base64
    bf-cbc         bf-cfb         bf-ecb         bf-ofb
    cast-cbc
    cast5-cbc      cast5-cfb      cast5-ecb      cast5-ofb
    des-cbc        des-cfb        des-ecb        des-ofb
    des-ede        des-ede-cbc    des-ede-cfb    des-ede-ofb
    des-ede3       des-ede3-cbc   des-ede3-cfb   des-ede3-ofb
    desx
    rc2-cbc        rc2-cfb        rc2-ecb        rc2-ofb
    rc2-40-cbc     rc2-64-cbc
    rc4            rc4-40
    ))

;; As of openssl-0.9.8 pkeys can only be used with certain types of digests.
;; openssl-0.9.9 is supposed to remove the restriction for digest types
(define pkey:rsa:digests '(ripemd160 sha1 sha224 sha256 sha384 sha512))
(define pkey:dsa:digests '(dss1))

(define (rsa-keygen bits [exp 65537])
  (let/fini ([ep (BN_new) BN_free])
    (BN_add_word ep exp)
    (let/error ([rsap (RSA_new) RSA_free]
                [evp (EVP_PKEY_new) EVP_PKEY_free])
      (RSA_generate_key_ex rsap bits ep)
      (EVP_PKEY_set1_RSA evp rsap)
      (new pkey-ctx% (impl pkey:rsa) (evp evp) (private? #t)))))

(define (dsa-keygen bits)
  (let/error ([dsap (DSA_new) DSA_free]
              [evp (EVP_PKEY_new) EVP_PKEY_free])
    (DSA_generate_parameters_ex dsap bits)
    (DSA_generate_key dsap)
    (EVP_PKEY_set1_DSA evp dsap)
    (new pkey-ctx% (impl pkey:dsa) (evp evp) (private? #t))))

(define EVP_PKEY_RSA	6)
(define EVP_PKEY_DSA	116)

(define pkey:rsa
  (new pkey-impl%
       (name "RSA")
       (pktype EVP_PKEY_RSA)
       (keygen rsa-keygen)
       (ok-digests pkey:rsa:digests)
       (encrypt-ok? #t)))

(define pkey:dsa
  (new pkey-impl%
       (name "RSA")
       (pktype EVP_PKEY_DSA)
       (keygen dsa-keygen)
       (ok-digests pkey:dsa:digests)
       (encrypt-ok? #f)))

(define pkey-table (hasheq 'rsa pkey:rsa 'dsa pkey:dsa))

;; ============================================================

(define ssl-factory%
  (class* factory-base% (factory<%>)
    (super-new)

    (define/override (get-digest* spec)
      (let ([name-string (hash-ref libcrypto-digests spec #f)])
        (and name-string (EVP_get_digestbyname name-string))))

    (define/override (get-cipher* spec)
      (match spec
        [(list (? symbol? name-sym) 'stream)
         (match (assq name-sym libcrypto-ciphers)
           [(list name-sym '(stream) #f name-string)
            (make-cipher spec (EVP_get_cipherbyname name-string))]
           [_ #f])]
        [(list (? symbol? name-sym) (? symbol? mode))
         (match (assq name-sym libcrypto-ciphers)
           [(list name-sym modes keys name-string)
            (and (memq mode modes)
                 (cond [keys
                        (for/list ([key (in-list keys)])
                          (define s (format "~a-~a-~a" name-string key mode))
                          (cons (quotient key 8)
                                (make-cipher spec (EVP_get_cipherbyname s))))]
                       [else
                        (define s (format "~a-~a" name-string mode))
                        (make-cipher spec (EVP_get_cipherbyname s))]))]
           [_ #f])]))

    (define/private (make-cipher spec evp)
      (and evp (new cipher-impl% (spec spec) (cipher evp))))

    ;; ----

    (define/override (get-pkey name-sym)
      (hash-ref pkey-table name-sym #f))

    (define/override (get-random)
      random-impl)
    ))

(define ssl-factory (new ssl-factory%))
