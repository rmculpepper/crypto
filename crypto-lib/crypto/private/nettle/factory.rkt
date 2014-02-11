;; Copyright 2013-2014 Ryan Culpepper
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
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt"
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
    [sha512    "sha512"]))

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

(define block-modes '(ecb cbc ctr gcm))

(define stream-ciphers
  `(;;[Name String/([KeySize String] ...)]
    [salsa20 "salsa20"]
    [salsa20r12 "salsa20r12"]
    [rc4 "arcfour128"]
    ;; "arctwo40", "arctwo64", "arctwo128"
    ))

;; ----------------------------------------

(define nettle-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest)
    (super-new)

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
      (or (match (assq (car spec) block-ciphers)
            [(list _ gcm-ok? alg)
             (and (memq (cadr spec) block-modes)
                  (if (eq? (cadr spec) 'gcm) gcm-ok? #t)
                  (alg->cipher alg))]
            [_ #f])
          (match (assq (car spec) stream-ciphers)
            [(list _ alg)
             (alg->cipher alg)]
            [_ #f])))

    (define/private (get-nc spec algid)
      (match (assoc algid nettle-all-ciphers)
        [(list _ nc)
         (new nettle-cipher-impl% (spec spec) (factory this) (nc nc))]
        [_ #f]))

    (define/override (get-kdf spec)
      (match spec
        [(list 'pbkdf2 'hmac di-spec)
         (let ([di (get-digest di-spec)])
           (and di (new nettle-pbkdf2-impl% (spec spec) (factory this) (di di))))]
        [_ #f]))
    ))

(define nettle-factory (new nettle-factory%))
