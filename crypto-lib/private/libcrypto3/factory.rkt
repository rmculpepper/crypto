;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/factory.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt")
(provide libcrypto-factory)

(define libcrypto-digests
  #hasheq(;; DigestSpec => String
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
    [chacha20 (stream) #f "chacha20"] ;; libcrypto reports wrong IV length
    [chacha20-poly1305 (stream) #f "chacha20-poly1305"]))

;; ----------------------------------------

(define libcrypto3-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher get-pk get-kdf)
    (super-new [ok? libcrypto3-ok?]
               [load-error #f])

    (field [libctx (and libcrypto3-ok? (OSSL_LIB_CTX_new))])
    (when libctx
      (OSSL_PROVIDER_load libctx "default")
      (OSSL_PROVIDER_load libctx "legacy"))

    (define/public (get-libctx) libctx)

    (define/override (get-name) 'libcrypto)
    (define/override (get-version)
      (and libcrypto3-ok?
           (list (OPENSSL_version_major)
                 (OPENSSL_version_minor)
                 (OPENSSL_version_patch))))

    (define/override (-get-digest info)
      (define evp (-get-digest-evp (send info get-spec)))
      (and evp (new libcrypto3-digest-impl% (info info) (factory this) (md evp))))

    (define/public (-get-digest-evp spec)
      (define name-string (hash-ref libcrypto-digests spec #f))
      (and name-string (EVP_MD_fetch libctx name-string #f)))

    (define/public (get-digest-lcname dspec)
      ;; Does not guarantee that digest is available from libctx.
      (define name (hash-ref libcrypto-digests dspec #f))
      (and (string? name) name))

    (define/override (-get-cipher info)
      (define evp/s (-get-cipher-evp (send info get-cipher-name) (send info get-mode)))
      (make-cipher info evp/s))

    (define/private (-get-cipher-evp cipher-name mode)
      (case mode
        [(stream)
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ '(stream) #f name-string)
            (EVP_CIPHER_fetch libctx name-string #f)]
           [_ #f])]
        [else
         (match (assq cipher-name libcrypto-ciphers)
           [(list _ modes keys name-string)
            (and (memq mode modes)
                 (cond [keys
                        (for/list ([key (in-list keys)])
                          (define s (format "~a-~a-~a" name-string key mode))
                          (cons (quotient key 8) (EVP_CIPHER_fetch libctx s #f)))]
                       [else
                        (define s (format "~a-~a" name-string mode))
                        (EVP_CIPHER_fetch libctx s #f)]))]
           [_ #f])]))

    (define/private (make-cipher info evp/s)
      (cond [(list? evp/s)
             (for/list ([keylen+evp (in-list evp/s)] #:when (cdr keylen+evp))
               (cons (car keylen+evp) (make-cipher info (cdr keylen+evp))))]
            [evp/s
             (new libcrypto3-cipher-impl% (info info) (factory this) (cipher evp/s))]
            [else #f]))

    (define/override (-get-pk spec)
      (case spec
        [(rsa) (new libcrypto3-rsa-impl% (factory this))]
        [(dsa) (new libcrypto3-dsa-impl% (factory this))]
        [(dh)  (new libcrypto3-dh-impl%  (factory this))]
        [(ec)  (new libcrypto3-ec-impl%  (factory this))]
        [(eddsa) (new libcrypto3-eddsa-impl% (factory this))]
        [(ecx) (new libcrypto3-ecx-impl% (factory this))]
        [else #f]))

    (define/override (-get-pk-reader)
      (new libcrypto3-read-key% (factory this)))

    (define/override (-get-kdf spec)
      (define (fetch kdf-name)
        (EVP_KDF_fetch libctx kdf-name #f))
      (define (make-impl evp params0)
        (new libcrypto3-kdf-impl% (factory this) (spec spec)
             (evp evp) (params0 params0)))
      (define (check/get-digest-name dspec)
        (define di (get-digest dspec))
        (and (is-a? di libcrypto3-digest-impl%) ;; can't use mac-as-digest
             (EVP_MD_get0_name (get-field md di))))
      (match spec
        ['scrypt
         (define evp (fetch "scrypt"))
         (and evp (make-impl evp null))]
        [(list 'pbkdf2 'hmac di)
         (define evp (fetch "pbkdf2"))
         (define dname (check/get-digest-name di))
         (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
        [(list 'hkdf di)
         (define evp (fetch "hkdf"))
         (define dname (check/get-digest-name di))
         (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
        [(list 'concat di)
         (define evp (fetch "ssdf"))
         (define dname (check/get-digest-name di))
         (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
        [(list 'concat 'hmac di)
         (define evp (fetch "ssdf"))
         (define dname (check/get-digest-name di))
         (and evp dname (make-impl evp `((#"digest" utf8-string ,dname)
                                         (#"mac" utf8-string "hmac"))))]
        [(list 'ans-x9.63 di)
         (define evp (fetch "X963KDF"))
         (define dname (check/get-digest-name di))
         (and evp dname (make-impl evp `((#"digest" utf8-string ,dname))))]
        [_ (super -get-kdf spec)]))

    ;; ----------------------------------------

    (define/override (info key)
      (case key
        ;; OpenSSL_info keys
        [(OPENSSL_INFO_CONFIG_DIR)
         (OPENSSL_info OPENSSL_INFO_CONFIG_DIR)]
        [(OPENSSL_INFO_ENGINES_DIR)
         (OPENSSL_info OPENSSL_INFO_ENGINES_DIR)]
        [(OPENSSL_INFO_MODULES_DIR)
         (OPENSSL_info OPENSSL_INFO_MODULES_DIR)]
        [(OPENSSL_INFO_DSO_EXTENSION)
         (OPENSSL_info OPENSSL_INFO_DSO_EXTENSION)]
        [(OPENSSL_INFO_DIR_FILENAME_SEPARATOR)
         (OPENSSL_info OPENSSL_INFO_DIR_FILENAME_SEPARATOR)]
        [(OPENSSL_INFO_LIST_SEPARATOR)
         (OPENSSL_info OPENSSL_INFO_LIST_SEPARATOR)]
        [(OPENSSL_INFO_SEED_SOURCE)
         (OPENSSL_info OPENSSL_INFO_SEED_SOURCE)]
        [(OPENSSL_INFO_CPU_SETTINGS)
         (OPENSSL_info OPENSSL_INFO_CPU_SETTINGS)]
        ;; OpenSSL_version keys
        [(OPENSSL_VERSION)
         (OpenSSL_version OPENSSL_VERSION)]
        [(OPENSSL_CFLAGS)
         (OpenSSL_version OPENSSL_CFLAGS)]
        [(OPENSSL_BUILT_ON)
         (OpenSSL_version OPENSSL_BUILT_ON)]
        [(OPENSSL_PLATFORM)
         (OpenSSL_version OPENSSL_PLATFORM)]
        [(OPENSSL_DIR)
         (OpenSSL_version OPENSSL_DIR)]
        [(OPENSSL_ENGINES_DIR)
         (OpenSSL_version OPENSSL_ENGINES_DIR)]
        [(OPENSSL_VERSION_STRING)
         (OpenSSL_version OPENSSL_VERSION_STRING)]
        [(OPENSSL_FULL_VERSION_STRING)
         (OpenSSL_version OPENSSL_FULL_VERSION_STRING)]
        [(OPENSSL_MODULES_DIR)
         (OpenSSL_version OPENSSL_MODULES_DIR)]
        [(OPENSSL_CPU_INFO)
         (OpenSSL_version OPENSSL_CPU_INFO)]
        ;; OpenSSL all
        [(openssl-info)
         (map (lambda (sym) (list sym (info sym)))
              '(OPENSSL_VERSION
                OPENSSL_CFLAGS
                OPENSSL_BUILT_ON
                OPENSSL_PLATFORM
                ;OPENSSL_DIR
                ;OPENSSL_ENGINES_DIR
                OPENSSL_VERSION_STRING
                OPENSSL_FULL_VERSION_STRING
                ;OPENSSL_MODULES_DIR
                OPENSSL_CPU_INFO
                OPENSSL_INFO_CONFIG_DIR
                OPENSSL_INFO_ENGINES_DIR
                OPENSSL_INFO_MODULES_DIR
                OPENSSL_INFO_DSO_EXTENSION
                OPENSSL_INFO_DIR_FILENAME_SEPARATOR
                OPENSSL_INFO_LIST_SEPARATOR
                OPENSSL_INFO_SEED_SOURCE
                OPENSSL_INFO_CPU_SETTINGS))]
        ;; Standard info
        [(all-ec-curves)
         (and (get-pk 'ec) (sort (hash-keys curve-name=>lcname) symbol<?))]
        [(all-eddsa-curves)
         (and (get-pk 'eddsa) '(ed25519 ed448))]
        [(all-ecx-curves)
         (and (get-pk 'ecx) '(x25519 x448))]
        [else (super info key)]))

    (define/override (print-lib-info)
      (super print-lib-info)
      (when (and libcrypto (> (OpenSSL_version_num) 0))
        (printf " OpenSSL_version_num: #x~x\n" (OpenSSL_version_num)))
      (when libcrypto3-ok?
        (printf " OPENSSL_VERSION_TEXT: ~s\n" (OpenSSL_version OPENSSL_VERSION)))
      (when (and libcrypto (not libcrypto3-ok?))
        (printf " status: library version not supported!\n")))
    ))

(define libcrypto-factory (new libcrypto3-factory%))
