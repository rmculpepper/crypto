;; Copyright 2012 Ryan Culpepper
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
         racket/dict
         racket/syntax
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide gcrypt-factory)

(define digest-info
  `((md5        ,GCRY_MD_MD5        64)
    (sha1       ,GCRY_MD_SHA1       64)
    (ripemd160  ,GCRY_MD_RMD160     64) ;; Doesn't seem to be available!
    (md2        ,GCRY_MD_MD2        16)
    (haval      ,GCRY_MD_HAVAL      128)
    (sha224     ,GCRY_MD_SHA224     64)
    (sha256     ,GCRY_MD_SHA256     64)
    (sha384     ,GCRY_MD_SHA384     128)
    (sha512     ,GCRY_MD_SHA512     128)
    (md4        ,GCRY_MD_MD4        64)
    (whirlpool  ,GCRY_MD_WHIRLPOOL  64)
    #|
    (tiger      ,GCRY_MD_TIGER      #f)
    (tiger1     ,GCRY_MD_TIGER1     #f)
    (tiger2     ,GCRY_MD_TIGER2     #f)
    |#))

(define (cipher->algid cipher)
  (case cipher
    ;;GCRY_CIPHER_IDEA
    ;;GCRY_CIPHER_3DES
    ;;GCRY_CIPHER_CAST5
    ((blowfish) GCRY_CIPHER_BLOWFISH)
    ;;GCRY_CIPHER_SAFER_SK128
    ;;GCRY_CIPHER_DES_SK
    ((aes-128) GCRY_CIPHER_AES)
    ((aes-192) GCRY_CIPHER_AES192)
    ((aes-256) GCRY_CIPHER_AES256)
    ((twofish) GCRY_CIPHER_TWOFISH)
    ;;GCRY_CIPHER_ARCFOUR
    ;;GCRY_CIPHER_DES
    ((twofish-128) GCRY_CIPHER_TWOFISH128)
    ((serpent-128) GCRY_CIPHER_SERPENT128)
    ((serpent-192) GCRY_CIPHER_SERPENT192)
    ((serpent-256) GCRY_CIPHER_SERPENT256)
    ;;GCRY_CIPHER_RFC2268_40
    ;;GCRY_CIPHER_RFC2268_128
    ;;GCRY_CIPHER_SEED
    ((camellia-128) GCRY_CIPHER_CAMELLIA128)
    ((camellia-192) GCRY_CIPHER_CAMELLIA192)
    ((camellia-256) GCRY_CIPHER_CAMELLIA256)
    (else #f)))

(define cipher-info
  (for*/list ([cipher (in-list '(blowfish
                                 aes-128 aes-192 aes-256
                                 twofish twofish-128
                                 serpent-128 serpent-192 serpent-256
                                 camellia-128 camellia-192 camellia-256))]
              [mode '(ecb cbc)])
    (list (format-symbol "~a-~a" cipher mode) cipher mode)))

(define gcrypt-factory%
  (class* object% (#|factory<%>|#)
    (super-new)

    (define digest-table (make-hasheq))
    (define cipher-table (make-hasheq))

    (define/private (intern-digest name-sym)
      (cond [(hash-ref digest-table name-sym #f)
             => values]
            [(dict-ref digest-info name-sym #f)
             => (lambda (md+bs)
                  (let* ([md (car md+bs)]
                         [bs (cadr md+bs)]
                         [avail? (gcry_md_test_algo md)])
                    (and avail?
                         (let ([di (new digest-impl% (md md) (name name-sym) (blocksize bs))])
                           (hash-set! digest-table name-sym di)
                           di))))]
            [else #f]))

    (define/private (intern-cipher name-sym)
      (cond [(hash-ref cipher-table name-sym #f)
             => values]
            [(dict-ref cipher-info name-sym #f)
             => (lambda (alg+mode)
                  (let ([ci (new cipher-impl%
                                 (name name-sym)
                                 (cipher (cipher->algid (car alg+mode)))
                                 (mode (cadr alg+mode)))])
                    (hash-set! cipher-table name-sym ci)
                    ci))]
            [else #f]))

    ;; ----

    (define/public (get-digest-by-name name)
      (intern-digest name))
    (define/public (get-cipher-by-name name)
      (intern-cipher name))
    ))

(define gcrypt-factory (new gcrypt-factory%))
