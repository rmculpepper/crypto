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
         racket/string
         ffi/unsafe
         "../common/interfaces.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "ffi.rkt"
         "macros.rkt")
(provide ssl-factory)

(define all-digest-names
  '(md5 ripemd160 sha1 sha224 sha256 sha384 sha512))

;; FIXME: des-ede-ecb, des-ede3-ecb ???
(define all-cipher-names
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
  (class* object% (factory<%>)
    (super-new)

    (define digest-table (make-hasheq))
    (define cipher-table (make-hasheq))

    (define/private (intern-digest name-sym)
      (cond [(hash-ref digest-table name-sym #f)
             => values]
            [(EVP_get_digestbyname (symbol->string name-sym))
             => (lambda (md)
                  (let ([di (new digest-impl% (md md) (name name-sym))])
                    (hash-set! digest-table name-sym di)
                    di))]
            [else #f]))

    (define/private (intern-cipher name-sym)
      (cond [(hash-ref cipher-table name-sym #f)
             => values]
            [(EVP_get_cipherbyname (symbol->string name-sym))
             => (lambda (cipher)
                  (let ([ci (new cipher-impl% (cipher cipher) (name name-sym))])
                    (hash-set! cipher-table name-sym ci)
                    ci))]
            [else #f]))

    ;; ----

    (define/public (get-digest-by-name name)
      (intern-digest name))

    (define/public (get-cipher-by-name name)
      (intern-cipher name))

    (define/public (get-cipher family param mode)
      (let* ([parts (for/list ([p (list family param mode)] #:when p)
                      (string-downcase (format "~a")))]
             [name (string->symbol (string-join parts "-"))])
        (intern-cipher name)))

    (define/public (get-pkey-by-name name-sym)
      (hash-ref pkey-table name-sym #f))
    ))

(define ssl-factory (new ssl-factory%))
