;; Copyright 2013-2018 Ryan Culpepper
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
         "../common/catalog.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
         "pkey.rkt"
         "kdf.rkt")
(provide nettle-factory)

;; ----------------------------------------

(define digests
  `(;;[Name     String]
    [md2       "md2"]
    [md4       "md4"]
    [md5       "md5"]
    [ripemd160 "ripemd160"]
    [sha1      "sha1"]
    [sha224    "sha224"]
    [sha256    "sha256"]
    [sha384    "sha384"]
    [sha512    "sha512"]
    [sha3-224  "sha3_224"]
    [sha3-256  "sha3_256"]
    [sha3-384  "sha3_384"]
    [sha3-512  "sha3_512"]
    ))

;; ----------------------------------------

;; FIXME: Probably ok to skip multikeylen indirection, since
;; "aes128" cipher can probably actually support all legal keylens,
;; it just *advertises* 128-bit keys.

(define block-ciphers
  `(;;[Name GCMok? String/([KeySize String] ...)]
    [aes #t ([128 "aes128"]
             [192 "aes192"]
             [256 "aes256"])]
    [blowfish #f "blowfish"]
    [camellia #t ([128 "camellia128"]
                  [192 "camellia192"]
                  [256 "camellia256"])]
    [cast128 #f ([128 "cast128"])]
    [serpent #t ([128 "serpent128"]
                 [192 "serpent192"]
                 [256 "serpent256"])]
    [twofish #t ([128 "twofish128"]
                 [192 "twofish192"]
                 [256 "twofish256"])]))

(define block-modes `(ecb cbc ctr
                      ,@(if nettle_gcm_set_key '(gcm) '())
                      ,@(if nettle_eax_set_key '(eax) '())))

(define stream-ciphers
  `(;;[Name String/([KeySize String] ...)]
    [salsa20 "salsa20"]
    [salsa20r12 "salsa20r12"]
    [chacha20 "chacha"]
    [rc4 "arcfour128"]
    [chacha20-poly1305 "chacha-poly1305"]
    ;; "arctwo40", "arctwo64", "arctwo128"
    ))

(define stream-modes '(stream)) ;; FIXME: poly1305 (but only for chacha20)

;; ----------------------------------------

(define nettle-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher)
    (super-new)

    (define/override (get-name) 'nettle)

    (define/override (get-digest* spec)
      (cond [(assq spec digests)
             => (lambda (entry)
                  (let ([algid (cadr entry)])
                    (cond [(assoc algid nettle-hashes)
                           => (lambda (entry)
                                (let ([nh (cadr entry)])
                                  (new nettle-digest-impl%
                                       (spec spec)
                                       (factory this)
                                       (nh nh))))]
                          [else #f])))]
            [else #f]))

    (define/override (get-cipher* spec)
      (define (alg->cipher alg)
        (cond [(string? alg)
               (get-nc spec alg)]
              [else
               (for/list ([keylen+algid (in-list alg)])
                 (cons (quotient (car keylen+algid) 8)
                       (get-nc spec (cadr keylen+algid))))]))
      (or (match (assq (cipher-spec-algo spec) block-ciphers)
            [(list _ gcm-ok? alg)
             (and (memq (cipher-spec-mode spec) block-modes)
                  (if (memq (cipher-spec-mode spec) '(gcm eax)) gcm-ok? #t)
                  (alg->cipher alg))]
            [_ #f])
          (match (assq (cipher-spec-algo spec) stream-ciphers)
            [(list _ alg)
             (alg->cipher alg)]
            [_ #f])))

    (define/private (get-nc spec algid)
      (match (assoc algid nettle-all-ciphers)
        [(list _ nc)
         (new nettle-cipher-impl% (spec spec) (factory this) (nc nc))]
        [_ #f]))

    (define/override (get-pk* spec)
      (case spec
        [(rsa) (new nettle-rsa-impl% (factory this))]
        [(dsa) (new nettle-dsa-impl% (factory this))]
        [else #f]))

    (define nettle-read-key (new nettle-read-key% (factory this)))
    (define/override (get-pk-reader)
      nettle-read-key)

    (define/override (get-kdf spec)
      (match spec
        [(list 'pbkdf2 'hmac di-spec)
         (let ([di (get-digest di-spec)])
           (and di (new nettle-pbkdf2-impl% (spec spec) (factory this) (di di))))]
        [_ #f]))

    ;; ----

    (define random-ctx #f)
    (define/public (get-random-ctx)
      (unless random-ctx
        (set! random-ctx (make-yarrow256-ctx)))
      (unless (nettle_yarrow256_is_seeded random-ctx)
        (nettle_yarrow256_seed random-ctx (crypto-random-bytes YARROW256_SEED_FILE_SIZE)))
      random-ctx)

    (define/private (make-yarrow256-ctx)
      (define ctx (malloc YARROW256_CTX_SIZE 'atomic-interior))
      (cpointer-push-tag! ctx yarrow256_ctx-tag)
      (nettle_yarrow256_init ctx 0 #f)
      ctx)

    (define/public (refresh-entropy)
      ;; If random-ctx doesn't exist, it doesn't need reseeding.
      (when random-ctx
        (nettle_yarrow256_seed random-ctx (crypto-random-bytes YARROW256_SEED_FILE_SIZE))))

    ;; ----

    (define/public (print-info)
      (printf "Library info:\n")
      (printf " Version: ~s.~s\n" (or (nettle_version_major) '?) (or (nettle_version_minor) '?))
      (printf "Available digests:\n")
      (for ([digest (map car digests)])
        (when (get-digest digest)
          (printf " ~v\n" digest)))
      (printf "Available ciphers:\n")
      (for ([cipher (map car block-ciphers)])
        (for ([mode (in-list block-modes)])
          (when (get-cipher (list cipher mode))
            (printf " ~v\n" (list cipher mode)))))
      (for ([cipher (map car stream-ciphers)])
        (when (get-cipher (list cipher 'stream))
          (printf " ~v\n" (list cipher 'stream))))
      (printf "Available PK:\n")
      (for ([pk '(rsa dsa)])
        ;; FIXME: check impl avail???
        (printf " ~v\n" pk))
      #|
      (printf "Available EC named curves:\n")
      |#
      (printf "Available KDFs:\n")
      (printf " `(pbkdf hmac ,DIGEST)  ;; for all digests listed above\n")
      (void))

    ))

(define nettle-factory (new nettle-factory%))
