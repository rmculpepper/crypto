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
(require racket/class
         racket/match
         "../common/interfaces.rkt"
         "../common/factory.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt"
         "ffi.rkt")
(provide libcrypto-factory
         libcrypto1-factory
         libcrypto3-factory)

;; Note: libcrypto ~1.1 has blake2s-256 and blake2b-512, limited (no
;; support for keys) so don't add here.

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
          [sha512    . "sha512"]
          [sha512/224 . "sha512-224"]
          [sha512/256 . "sha512-256"]
          [sha3-224  . "sha3-224"]
          [sha3-256  . "sha3-256"]
          [sha3-384  . "sha3-384"]
          [sha3-512  . "sha3-512"]
          ))

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
    [rc4 (stream) #f "rc4"]
    ;; [chacha20 (stream) #f "chacha20"] ;; libcrypto reports wrong IV length
    [chacha20-poly1305 (stream) #f "chacha20-poly1305"]))

;; ============================================================

(define libcrypto1-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher get-pk)
    (super-new [ok? libcrypto-ok?] [load-error libcrypto-load-error])

    (define/override (get-name) 'libcrypto)
    (define/override (get-version)
      (and (OpenSSL_version_num)
           (call-with-values (lambda () (parse-version (OpenSSL_version_num))) list)))

    (define/override (-get-digest info)
      (define evp (-get-digest-evp (send info get-spec)))
      (and evp (new libcrypto-digest-impl% (info info) (factory this) (md evp))))

    (define/public (-get-digest-evp spec)
      (define name-string (hash-ref libcrypto-digests spec #f))
      (and name-string (EVP_get_digestbyname name-string)))

    (define/override (-get-cipher info)
      (define evp/s (-get-cipher-evp (send info get-cipher-name) (send info get-mode)))
      (make-cipher info evp/s))

    (define/public (-get-cipher-evp cipher-name mode)
      (case mode
        [(stream)
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ '(stream) #f name-string)
            (EVP_get_cipherbyname name-string)]
           [_ #f])]
        [else
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ modes keys name-string)
            (and (memq mode modes)
                 (cond [keys
                        (for/list ([key (in-list keys)])
                          (define s (format "~a-~a-~a" name-string key mode))
                          (cons (quotient key 8) (EVP_get_cipherbyname s)))]
                       [else
                        (define s (format "~a-~a" name-string mode))
                        (EVP_get_cipherbyname s)]))]
           [_ #f])]))

    (define/private (make-cipher info evp/s)
      (cond [(list? evp/s)
             (for/list ([keylen+evp (in-list evp/s)] #:when (cdr keylen+evp))
               (cons (car keylen+evp) (make-cipher info (cdr keylen+evp))))]
            [evp/s
             (new libcrypto-cipher-impl% (info info) (factory this) (cipher evp/s))]
            [else #f]))

    (define/override (-get-pk spec)
      (case spec
        [(rsa) (new libcrypto-rsa-impl% (factory this))]
        [(dsa) (new libcrypto-dsa-impl% (factory this))]
        [(dh)  (new libcrypto-dh-impl%  (factory this))]
        [(ec)  (new libcrypto-ec-impl%  (factory this))]
        [(eddsa) (and (openssl-version>=? 1 1 1)
                      (new libcrypto-eddsa-impl% (factory this)))]
        [(ecx) (and (openssl-version>=? 1 1 1)
                    (new libcrypto-ecx-impl% (factory this)))]
        [else #f]))

    (define/override (-get-pk-reader)
      (new libcrypto-read-key% (factory this)))

    (define/override (-get-kdf spec)
      (match spec
        ['scrypt
         (and (openssl-version>=? 1 1 0)
              (new libcrypto-scrypt-impl% (spec spec) (factory this)))]
        [(list 'pbkdf2 'hmac di-spec)
         (let ([di (get-digest di-spec)])
           (and di (new libcrypto-pbkdf2-impl% (spec spec) (factory this) (di di))))]
        [_ (super -get-kdf spec)]))

    ;; ----

    (define/override (info key)
      (case key
        [(all-ec-curves)
         (and (get-pk 'ec) (sort (hash-keys curve-table) symbol<?))]
        [(all-eddsa-curves)
         (and (get-pk 'eddsa) '(ed25519 ed448))]
        [(all-ecx-curves)
         (and (get-pk 'ecx) '(x25519 x448))]
        [else (super info key)]))

    (define/override (print-lib-info)
      (super print-lib-info)
      (printf " version string: ~s\n" (OpenSSL_version SSLEAY_VERSION))
      (when (OpenSSL_version_num)
        (printf " OpenSSL_version_num: #x~x\n" (OpenSSL_version_num))
        (printf " built on: ~s\n" (OpenSSL_version SSLEAY_BUILT_ON)))
      (when (and libcrypto (not libcrypto-ok?))
        (printf " status: library version not supported!\n")))

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

;; ============================================================

(define libcrypto3-factory%
  (class libcrypto1-factory%
    (super-new)

    ;; The EVP_get{digest,cipher}byname interfaces still "work" in OpenSSL 3.0,
    ;; but they return EVP_{MD,CIPHER} objects that aren't fully "fetched", and
    ;; fetching may fail when they're first used (eg, for legacy algorithms). So
    ;; let's switch to eager fetching so we never falsely report an impl is
    ;; available when it isn't.

    (define/override (-get-digest-evp spec)
      (define name-string (hash-ref libcrypto-digests spec #f))
      (and name-string (EVP_MD_fetch #f name-string #f)))

    (define/override (-get-cipher-evp cipher-name mode)
      (case mode
        [(stream)
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ '(stream) #f name-string)
            (EVP_CIPHER_fetch #f name-string #f)]
           [_ #f])]
        [else
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ modes keys name-string)
            (and (memq mode modes)
                 (cond [keys
                        (for/list ([key (in-list keys)])
                          (define s (format "~a-~a-~a" name-string key mode))
                          (cons (quotient key 8) (EVP_CIPHER_fetch #f s #f)))]
                       [else
                        (define s (format "~a-~a" name-string mode))
                        (EVP_CIPHER_fetch #f s #f)]))]
           [_ #f])]))

    ;; ----

    (define/override (print-lib-info)
      (super print-lib-info)
      (printf " OPENSSL 3 API\n"))
    ))

;; ============================================================

(define libcrypto1-factory (new libcrypto1-factory%))
(define libcrypto3-factory (new libcrypto3-factory%))

(define libcrypto-factory
  (cond [(and libcrypto-ok? (openssl-version>=? 3 0 0))
         libcrypto3-factory]
        [else
         libcrypto1-factory]))
