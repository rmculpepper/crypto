;; Copyright 2018 Ryan Culpepper
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
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "../common/catalog.rkt"
         "ffi.rkt"
         "digest.rkt"
         "cipher.rkt")
(provide botan2-factory)

(define botan2-digests
  ;; from Botan/src/lib/hash/hash.cpp
  '([sha1        "SHA-1"]
    [sha224      "SHA-224"]
    [sha256      "SHA-256"]
    [sha384      "SHA-384"]
    [sha512      "SHA-512"]
    [ripemd160   "RIPEMD-160"]
    [whirlpool   "Whirlpool"]
    [md5         "MD5"]
    [blake2b-512 "Blake2b(512)"]
    [blake2b-384 "Blake2b(384)"]
    [blake2b-256 "Blake2b(256)"]
    [blake2b-160 "Blake2b(160)"]
    [sha3-512    "SHA-3(512)"]
    [sha3-384    "SHA-3(384)"]
    [sha3-256    "SHA-3(256)"]
    [sha3-224    "SHA-3(224)"]
    ;;["SHA-512-256"]
    ;;["Skein-512"] ;; options?
    ;;["SHAKE-128"]
    ;;["SHAKE-256"]
    ))

(define stream-ciphers
  '([salsa20    "Salsa20"]
    [salsa20r8  "Salsa20(8)"]
    [salsa20r12 "Salsa20(12)"]
    [chacha20   "ChaCha20"]
    [chacha20-poly1305 "ChaCha20Poly1305"]))

(define block-modes
  '([ctr "CTR"]
    [gcm "GCM"]
    [eax "EAX"]
    [ofb "OFB"]))

(define block-ciphers
  '([aes      ("AES" (16 24 32))]
    [aria     ("ARIA" (16 24 32))]
    [camellia ("Camellia" (16 24 32))]
    [serpent  "Serpent"]
    [twofish  "Twofish"]))

;; ----

(define botan2-factory%
  (class* factory-base% (factory<%>)
    (inherit get-digest get-cipher)
    (super-new [ok? botan-ok?])

    (define/override (get-name) 'botan2)

    (define/override (-get-digest info)
      (cond [(assoc (send info get-spec) botan2-digests)
             => (lambda (e)
                  (define ctx (botan_hash_init (cadr e)))
                  (and ctx (new botan2-digest-impl% (factory this) (info info) (master-ctx ctx))))]
            [else #f]))

    (define/override (-get-cipher info)
      (define spec (send info get-spec))
      (define mode (cipher-spec-mode spec))
      (define algo (cipher-spec-algo spec))
      (define (cipher bname)
        (and (botan_cipher_init bname 0)
             (new botan2-cipher-impl% (info info) (factory this) (bname bname))))
      (define (alt keylen bname)
        (cons keylen (cipher bname)))
      (cond [(eq? mode 'stream)
             (cond [(assq algo stream-ciphers)
                    => (lambda (se) (cipher (cadr se)))]
                   [else #f])]
            [(assq mode block-modes)
             => (lambda (me)
                  (define mode-str (cadr me))
                  (cond [(assq algo block-ciphers)
                         => (lambda (be)
                              (define rhs (cadr be))
                              (cond [(string? rhs)
                                     (cipher (format "~a/~a" rhs mode-str))]
                                    [(list? rhs)
                                     (define b-str (car rhs))
                                     (define keylens (cadr rhs))
                                     (for/list ([keylen (in-list keylens)])
                                       (define keybits (* 8 keylen))
                                       (alt keylen (format "~a-~a/~a" b-str keybits mode-str)))]))]
                        [else #f]))]
            [else #f]))

    ;; ----

    (define/override (info key)
      (case key
        [(version) (and botan-ok? (botan_version_string))]
        [(all-digests)
         (for/list ([de (in-list botan2-digests)]
                    #:when (get-digest (car de)))
           (car de))]
        [(all-ciphers)
         (append
          (for*/list ([se (in-list stream-ciphers)] [spec (in-value (list (car se) 'stream))]
                      #:when (get-cipher spec))
            spec)
          (for*/list ([be (in-list block-ciphers)] [me (in-list block-modes)]
                      [spec (in-value (list (car be) (car me)))]
                      #:when (get-cipher spec))
            spec))]
        [(all-pks) null]
        [(all-curves) null]
        [else (super info key)]))

    (define/override (print-info)
      (printf "Library info:\n")
      (printf " Version: ~v\n" (info 'version))
      (printf "Available digests:\n")
      (for ([di (in-list (info 'all-digests))])
        (printf " ~v\n" di))
      #|
      (printf "Available ciphers:\n")
      (for ([ci (in-list (info 'all-ciphers))])
        (printf " ~v\n" ci))
      |#
      (void))
    ))

(define botan2-factory (new botan2-factory%))
