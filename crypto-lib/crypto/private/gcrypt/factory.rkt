;; Copyright 2012-2013 Ryan Culpepper
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
         ffi/unsafe
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide gcrypt-factory)

;; ----------------------------------------

(define digests
  `(;;[Name     AlgId               BlockSize]
    (sha1       ,GCRY_MD_SHA1       64)
    (ripemd160  ,GCRY_MD_RMD160     64) ;; Doesn't seem to be available!
    (md2        ,GCRY_MD_MD2        16)
    (sha224     ,GCRY_MD_SHA224     64)
    (sha256     ,GCRY_MD_SHA256     64)
    (sha384     ,GCRY_MD_SHA384     128)
    (sha512     ,GCRY_MD_SHA512     128)
    (md4        ,GCRY_MD_MD4        64)
    (whirlpool  ,GCRY_MD_WHIRLPOOL  64)
    (tiger1     ,GCRY_MD_TIGER1     64)
    (tiger2     ,GCRY_MD_TIGER2     64)
    #|
    (haval      ,GCRY_MD_HAVAL      128)
    (tiger      ,GCRY_MD_TIGER      #f) ;; special old GnuPG-compat output order
    |#))

;; ----------------------------------------

(define ciphers
  `(;;[Name   ([KeySize AlgId] ...)]
    [cast128 ([128 ,GCRY_CIPHER_CAST5])]
    [blowfish ([128 ,GCRY_CIPHER_BLOWFISH])]
    [aes      ([128 ,GCRY_CIPHER_AES]
               [192 ,GCRY_CIPHER_AES192]
               [256 ,GCRY_CIPHER_AES256])]
    [twofish  ([128 ,GCRY_CIPHER_TWOFISH128]
               [256 ,GCRY_CIPHER_TWOFISH])]
    [serpent  ([128 ,GCRY_CIPHER_SERPENT128]
               [192 ,GCRY_CIPHER_SERPENT192]
               [256 ,GCRY_CIPHER_SERPENT256])]
    [camellia ([128 ,GCRY_CIPHER_CAMELLIA128]
               [192 ,GCRY_CIPHER_CAMELLIA192]
               [256 ,GCRY_CIPHER_CAMELLIA256])]
    [des      ([64 ,GCRY_CIPHER_DES])] ;; takes key as 64 bits, high bits ignored
    [des-ede3 ([192 ,GCRY_CIPHER_3DES])] ;; takes key as 192 bits, high bits ignored
    ;; [rc4   ([??? ,GCRY_CIPHER_ARCFOUR])]
    ;; [idea  ([??? ,GCRY_CIPHER_IDEA])]
    ))

(define modes
  `(;[Mode ModeId]
    [ecb    ,GCRY_CIPHER_MODE_ECB]
    [cbc    ,GCRY_CIPHER_MODE_CBC]
    #|
    FIXME: re-enable
    [cfb    ,GCRY_CIPHER_MODE_CFB]
    [ofb    ,GCRY_CIPHER_MODE_OFB]
    [ctr    ,GCRY_CIPHER_MODE_CTR]
    |#
    [stream ,GCRY_CIPHER_MODE_STREAM]))

;; ----------------------------------------

(define gcrypt-random-impl%
  (class* object% (random-impl<%>)
    (super-new)
    (define/public (get-spec) 'random)
    (define/public (get-factory) gcrypt-factory)
    (define/public (random-bytes! buf start end level)
      ;; FIXME: better mapping to quality levels
      (gcry_randomize (ptr-add buf start) (- end start)
                      (case level
                        [(very-strong) GCRY_VERY_STRONG_RANDOM]
                        [else GCRY_STRONG_RANDOM])))
    (define/public (ok?) #t)
    (define/public (can-add-entropy?) #f)
    (define/public (add-entropy buf entropy-in-bytes) (void))
    ))

(define gcrypt-random-impl (new gcrypt-random-impl%))

;; ----------------------------------------

(define gcrypt-factory%
  (class* factory-base% (factory<%>)
    (super-new)

    (define/override (get-digest* spec)
      (cond [(assq spec digests)
             => (lambda (entry)
                  (match entry
                    [(list _ algid blocksize)
                     (and (gcry_md_test_algo algid)
                          (new gcrypt-digest-impl%
                               (spec spec)
                               (factory this)
                               (md algid)
                               (blocksize blocksize)))]
                    [_ #f]))]
            [else #f]))

    (define/override (get-cipher* spec)
      (cond [(and (assq (cadr spec) modes)
                  (assq (car spec) ciphers))
             => (lambda (entry)
                  (match entry
                    [(list _ keylens+algids)
                     (for/list ([keylen+algid (in-list keylens+algids)])
                       (cons (quotient (car keylen+algid) 8)
                             (and (gcry_cipher_test_algo (cadr keylen+algid))
                                  (new gcrypt-cipher-impl%
                                       (spec spec)
                                       (factory this)
                                       (cipher (cadr keylen+algid))
                                       (mode (cadr (assq (cadr spec) modes)))))))]
                    [_ #f]))]
            [else #f]))

    (define/override (get-random)
      gcrypt-random-impl)
    ))

(define gcrypt-factory (new gcrypt-factory%))
