;; Copyright 2012-2014 Ryan Culpepper
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
         "kdf.rkt"
         "ffi.rkt")
(provide libcrypto-factory)

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
    [aes (cbc cfb #|cfb1 cfb8|# ctr ecb gcm ofb #|xts|#) (128 192 256) "aes"]
    [blowfish (cbc cfb ecb ofb) #f "bf"]
    [camellia (cbc cfb #|cfb1 cfb8|# ecb ofb) (128 192 256) "camellia"]
    [cast128 (cbc cfb ecb ofb) #f "cast5"]
    [des (cbc cfb #|cfb1 cfb8|# ecb ofb) #f "des"]
    [des-ede2 (cbc cfb ofb) #f "des-ede"] ;; ECB mode???
    [des-ede3 (cbc cfb ofb) #f "des-ede3"] ;; ECB mode???
    [rc4 (stream) #f "rc4"]))

#|
;; As of openssl-0.9.8 pkeys can only be used with certain types of digests.
;; openssl-0.9.9 is supposed to remove the restriction for digest types
(define pkey:rsa:digests '(ripemd160 sha1 sha224 sha256 sha384 sha512))
(define pkey:dsa:digests '(dss1))
|#

;; ============================================================

(define libcrypto-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher)
    (super-new)

    (define/override (get-name) 'libcrypto)

    (define/override (get-digest* spec)
      (let* ([name-string (hash-ref libcrypto-digests spec #f)]
             [evp (and name-string (EVP_get_digestbyname name-string))])
        (and evp (new libcrypto-digest-impl% (spec spec) (factory this) (md evp)))))

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
      (and evp (new libcrypto-cipher-impl% (spec spec) (factory this) (cipher evp))))

    ;; ----

    (define/override (get-pk* spec)
      (case spec
        [(rsa) (new libcrypto-rsa-impl% (factory this))]
        [(dsa) (new libcrypto-dsa-impl% (factory this))]
        [(dh)  (new libcrypto-dh-impl%  (factory this))]
        [(ec)  (new libcrypto-ec-impl%  (factory this))]
        [else #f]))


    (define libcrypto-read-key (new libcrypto-read-key% (factory this)))
    (define/override (get-pk-reader)
      libcrypto-read-key)

    (define/override (get-kdf spec)
      (match spec
        [(list 'pbkdf2 'hmac di-spec)
         (let ([di (get-digest di-spec)])
           (and di (new libcrypto-pbkdf2-impl% (spec spec) (factory this) (di di))))]
        [_ #f]))

    ;; ----

    (define/public (print-info)
      (printf "Library info:\n")
      (printf " SSLeay() = ~x\n" (SSLeay))
      (printf " SSLEAY_VERSION: ~s\n" (SSLeay_version SSLEAY_VERSION))
      (printf " SSLEAY_BUILT_ON: ~s\n" (SSLeay_version SSLEAY_BUILT_ON))
      (printf "Available digests:\n")
      (for ([digest (in-hash-keys libcrypto-digests)])
        (when (get-digest digest)
          (printf " ~v\n" digest)))
      (printf "Available ciphers:\n")
      (for ([cipher-entry (in-list libcrypto-ciphers)])
        (define cipher (car cipher-entry))
        (for ([mode (in-list (cadr cipher-entry))])
          (when (get-cipher (list cipher mode))
            (printf " ~v\n" (list cipher mode)))))
      (printf "Available PK:\n")
      (for ([pk '(rsa dsa dh ec)])
        (printf " ~v\n" pk))
      (printf "Available EC named curves:\n")
      (let ([curve-names (make-hash)])
        (for ([curve-info (enumerate-builtin-curves)])
          (hash-set! curve-names (caddr curve-info) #t)
          (printf " ~v  ;; ~s\n" (caddr curve-info) (cadr curve-info)))
        (for ([alias-entry curve-aliases])
          (for ([alias alias-entry])
            (unless (hash-ref curve-names alias #f)
              (define target
                (for/or ([name alias-entry]
                         #:when (hash-ref curve-names name #f))
                  name))
              (when target
                (printf " ~v  ;; alias for ~v\n" alias target))))))
      (printf "Available KDFs:\n")
      (printf " `(pbkdf hmac ,DIGEST)  ;; for all digests listed above\n")
      (void))

    (define/public (print-internal-info)
      (printf "Library info:\n")
      (for ([desc+int `((SSLEAY_VERSION  ,SSLEAY_VERSION)
                        (SSLEAY_CFLAGS   ,SSLEAY_CFLAGS)
                        (SSLEAY_BUILT_ON ,SSLEAY_BUILT_ON)
                        (SSLEAY_PLATFORM ,SSLEAY_PLATFORM)
                        (SSLEAY_DIR      ,SSLEAY_DIR))])
        (printf " ~s: ~s\n" (car desc+int) (SSLeay_version (cadr desc+int))))
      ;; Digests
      (printf "Digests:\n")
      (EVP_MD_do_all_sorted
       (lambda (m from to)
         (if m
             (printf " digest ~s\n" from)
             (printf " alias ~s => ~s\n" from to))))
      ;; Ciphers
      (printf "Ciphers:\n")
      (EVP_CIPHER_do_all_sorted
       (lambda (c from to)
         (if c
             (printf " cipher ~s\n" from)
             (printf " alias ~s => ~s\n" from to))))
      ;; --
      (void))
    ))

(define libcrypto-factory (new libcrypto-factory%))
