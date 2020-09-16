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
         "../common/factory.rkt"
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

(define block-modes `(ecb cbc ctr ,@(if gcm-ok? '(gcm) '()) ,@(if eax-ok? '(eax) '())))

(define stream-ciphers
  `(;;[Name String/([KeySize String] ...)]
    [salsa20 "salsa20"]
    [salsa20r12 "salsa20r12"]
    [chacha20 "chacha"]
    [rc4 "arcfour128"]
    [chacha20-poly1305 "chacha-poly1305"]
    ;; "arctwo40", "arctwo64", "arctwo128"
    ))


;; ----------------------------------------

(define nettle-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher get-pk get-kdf)
    (super-new [ok? nettle-ok?] [load-error (or nettle-load-error hogweed-load-error)])

    (define/override (get-name) 'nettle)
    (define/override (get-version)
      (and nettle-ok? (list (nettle_version_major) (nettle_version_minor))))

    (define/override (-get-digest info)
      (define spec (send info get-spec))
      (cond [(assq spec digests)
             => (lambda (entry)
                  (let ([algid (cadr entry)])
                    (cond [(assoc algid nettle-hashes)
                           => (lambda (entry)
                                (let ([nh (cadr entry)])
                                  (new nettle-digest-impl%
                                       (info info)
                                       (factory this)
                                       (nh nh))))]
                          [else #f])))]
            [else #f]))

    (define/override (-get-cipher info)
      (define spec (send info get-spec))
      (define (alg->cipher alg)
        (cond [(string? alg)
               (get-nc info alg)]
              [else
               (for/list ([keylen+algid (in-list alg)])
                 (cons (quotient (car keylen+algid) 8)
                       (get-nc info (cadr keylen+algid))))]))
      (or (match (assq (cipher-spec-algo spec) block-ciphers)
            [(list _ gcm/eax-ok? alg)
             (and (memq (cipher-spec-mode spec) block-modes)
                  (if (memq (cipher-spec-mode spec) '(gcm eax)) gcm/eax-ok? #t)
                  (alg->cipher alg))]
            [_ #f])
          (match (assq (cipher-spec-algo spec) stream-ciphers)
            [(list _ alg)
             (alg->cipher alg)]
            [_ #f])))

    (define/private (get-nc info algid)
      (match (assoc algid nettle-all-ciphers)
        [(list _ nc)
         (new nettle-cipher-impl% (info info) (factory this) (nc nc))]
        [_ #f]))

    (define/override (-get-pk spec)
      (case spec
        [(rsa) (and rsa-ok? (new nettle-rsa-impl% (factory this)))]
        [(dsa) (and new-dsa-ok? (new nettle-dsa-impl% (factory this)))]
        [(ec) (and ec-ok? (new nettle-ec-impl% (factory this)))]
        [(eddsa) (and (or ed25519-ok? ed448-ok?) (new nettle-eddsa-impl% (factory this)))]
        [(ecx) (and (or x25519-ok? x448-ok?) (new nettle-ecx-impl% (factory this)))]
        [else #f]))

    (define/override (-get-pk-reader)
      (new nettle-read-key% (factory this)))

    (define/override (-get-kdf spec)
      (match spec
        [(list 'pbkdf2 'hmac di-spec)
         (let ([di (get-digest di-spec)])
           (and di (memq di-spec '(sha1 sha256))
                (new nettle-pbkdf2-impl% (spec spec) (factory this) (di di))))]
        [_ (super -get-kdf spec)]))

    ;; ----

    (define random-ctx #f)
    (define until-reseed (get-reseed-limit))

    (define/public (get-random-ctx)
      (set! until-reseed (sub1 until-reseed))
      (unless random-ctx
        (set! random-ctx (make-yarrow256-ctx)))
      (unless (and (nettle_yarrow256_is_seeded random-ctx) (> until-reseed 0))
        (nettle_yarrow256_seed random-ctx (crypto-random-bytes YARROW256_SEED_FILE_SIZE))
        (set! until-reseed (get-reseed-limit)))
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

    ;; Number of *requests* between reseeds. (Each request represents a variable
    ;; (potentially large) number of random bytes produced.)
    (define/private (get-reseed-limit) 100)

    ;; ----

    (define/override (info key)
      (case key
        [(all-ec-curves)
         (map car nettle-curves)]
        [(all-eddsa-curves)
         (append (if ed25519-ok? '(ed25519) '())
                 (if ed448-ok? '(ed448) '()))]
        [(all-ecx-curves)
         (append (if x25519-ok? '(x25519) '())
                 (if x448-ok? '(x448) '()))]
        [else (super info key)]))
    ))

(define nettle-factory (new nettle-factory%))
