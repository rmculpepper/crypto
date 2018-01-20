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
(require racket/string
         racket/match
         racket/list
         "error.rkt")
(provide (all-defined-out))

;; ============================================================
;; Digests

(define known-digests
  '#hasheq(;; symbol  ->   [Hash  Block [MaxKeyLen]]   -- sizes in bytes
           [md2         .  [ 16   16 ]]
           [md4         .  [ 16   64 ]]
           [md5         .  [ 16   64 ]]
           [ripemd160   .  [ 20   64 ]]
           [tiger1      .  [ 24   64 ]]
           [tiger2      .  [ 24   64 ]]
           [whirlpool   .  [ 64   64 ]] ;; Note: 3 versions, W-0 (2000), W-T (2001), W (2003)
           [sha0        .  [ 20   64 ]]
           [sha1        .  [ 20   64 ]]
           [sha224      .  [ 28   64 ]]
           [sha256      .  [ 32   64 ]]
           [sha384      .  [ 48   128]]
           [sha512      .  [ 64   128]]
           [sha3-224    .  [ 28   144]]
           [sha3-256    .  [ 32   136]]
           [sha3-384    .  [ 48   104]]
           [sha3-512    .  [ 64   72]]

           ;; the following take keys
           [blake2b-512 .  [ 64   128  64]] ;; blake2b up to 64 bytes
           [blake2b-384 .  [ 48   128  64]]
           [blake2b-256 .  [ 32   128  64]]
           [blake2b-160 .  [ 20   128  64]]
           [blake2s-256 .  [ 32   64   32]] ;; blake2s up to 32 bytes
           [blake2s-224 .  [ 28   64   32]]
           [blake2s-160 .  [ 20   64   32]]
           [blake2s-128 .  [ 16   64   32]]

           ;; the following are XOFs (extensible output functions) -- put #f for output size
           [shake128    .  [ #f   168]]
           [shake256    .  [ #f   136]]
           ))

;; A DigestSpec is a symbol in domain of known-digests.

(define (digest-spec? x)
  (and (hash-ref known-digests x #f) #t))

(define (digest-spec-size spec)
  (match (hash-ref known-digests spec #f)
    [(list* size block-size _) size]
    [_ #f]))

(define (digest-spec-block-size spec)
  (match (hash-ref known-digests spec #f)
    [(list* size block-size _) block-size]
    [_ #f]))

(define (digest-spec-max-key-size spec)
  (match (hash-ref known-digests spec #f)
    [(list size block-size max-key-size) max-key-size]
    [else #f]))

;; ============================================================

;; SizeSet is one of
;;  - (list nat ...+)
;;  - #s(varsize min-nat max-nat step-nat)
(struct varsize (min max step) #:prefab)

(define (size-set-contains? ss n)
  (match ss
    [(? list? ss)
     (and (member n ss) #t)]
    [(varsize min max step)
     (and (<= min n max) (zero? (remainder (- n min) step)))]
    [#f #f]))

(define (size-set->list ss)
  (match ss
    [(? list? sizes) sizes]
    [(varsize min max step) (range min (add1 max) step)]))

;; ============================================================
;; Block Ciphers and Modes

(define known-block-ciphers
  '#hasheq(;; symbol  -> (Block AllowedKeys)   -- sizes in bytes
           [aes        .  [ 16    (16 24 32)]]
           [des        .  [ 8     (8)]]      ;; key expressed as 8 bytes w/ parity bits
           [des-ede2   .  [ 8     (16)]]     ;; key expressed as 16 bytes w/ parity bits
           [des-ede3   .  [ 8     (24)]]     ;; key expressed as 24 bytes w/ parity bits
           [blowfish   .  [ 8     #s(varsize 4 56 1)]]
           [cast128    .  [ 8     #s(varsize 5 16 1)]]
           [camellia   .  [ 16    (16 24 32)]]
           [serpent    .  [ 16    #s(varsize 0 32 1)]]
           [twofish    .  [ 16    #s(varsize 8 32 1)]]
           [idea       .  [ 8     (16)]]
           ;; [rc5        .  [ 8     #s(varsize 0 255 1)]]
           ;; [rc5-64     .  [ 16    #s(varsize 0 255 1)]]
           ;; [rc6-64     .  [ 32    #s(varsize 0 255 1)]]
           ;; [cast256    .  [ 16    #s(varsize 16 32 4)]]
           ;; [rc6        .  [ 16    #s(varsize 0 255 1)]]
           ;; [mars       .  [ 16    #s(varsize 16 56 4)]] ;; aka Mars-2 ???
           ))

;; block-cipher-name? : Any -> Boolean
(define (block-cipher-name? x)
  (and (hash-ref known-block-ciphers x #f) #t))

;; block-cipher-block-size : Symbol -> Nat/#f
(define (block-cipher-block-size x)
  (cond [(hash-ref known-block-ciphers x #f) => car]
        [else #f]))

;; block-cipher-key-sizes : Symbol -> SizeSet
(define (block-cipher-key-sizes x)
  (cond [(hash-ref known-block-ciphers x #f) => cadr]
        [else #f]))

;; Block modes are complicated; some modes are defined only for
;; 128-bit block ciphers; others have variable-length IVs/nonces or
;; authentication tags.

(define known-block-modes '(ecb cbc ofb cfb ctr gcm ocb eax))

;; block-mode? : Any -> Boolean
(define (block-mode? x)
  (and (memq x known-block-modes) #t))

;; block-mode-type : Any -> (U 'block 'stream #f)
(define (block-mode-type mode)
  (case mode
    [(ecb cbc) 'block]
    [(ofb cfb ctr gcm ocb eax) 'stream]
    [else #f]))

;; block-mode-aead? : Symbol -> Boolean
(define (block-mode-aead? mode)
  (and (block-mode-default-auth-size mode) #t))

;; block-mode-default-auth-size : Symbol -> Nat/#f
(define (block-mode-default-auth-size mode)
  (case mode
    [(gcm ocb eax) 16]
    [else #f]))

;; block-mode-auth-size-ok? : Symbol Nat -> Boolean
(define (block-mode-auth-size-ok? mode size)
  (case mode
    [(gcm) (or (<= 12 size 16) (= size 8) (= size 4))]
    [(ocb eax) (<= 1 size 16)]
    [else #f]))

;; block-mode-block-size-ok? : Symbol Nat -> Boolean
(define (block-mode-block-size-ok? mode block-size)
  (case mode
    ;; EAX claims to be block-size agnostic, but nettle restricts to 128-bit block ciphers
    [(gcm ocb eax) (= block-size 16)]
    [else #t]))

;; block-mode-iv-sizes : Symbol Nat -> Nat or (list Nat SizeSet)
;; Returns recommended and allowed IV/nonce/counter sizes.
(define (block-mode-iv-sizes mode block-size)
  (case mode
    [(ecb)         0]
    [(cbc ofb cfb) block-size]
    [(ctr)         block-size]
    [(gcm)         '(12 #s(varsize 1 16 1))] ;; actual upper bound much higher
    [(ocb)         '(12 #s(varsize 0 15 1))] ;; "no more than 120 bits"
    [(eax)         '(12 #s(varsize 0 16 1))] ;; actually unrestricted
    [else #f]))

;; block-mode-default-iv-size : Symbol Nat -> Nat
(define (block-mode-default-iv-size mode block-size)
  (case mode
    [(ecb) 0]
    [(cbc ofb cfb ctr) block-size]
    [(gcm ocb eax) 12]
    [else #f]))

;; block-mode-iv-size-ok? : Symbol Nat Nat -> Boolean
(define (block-mode-iv-size-ok? mode block-size size)
  (case mode
    [(ecb)         (= size 0)]
    [(cbc ofb cfb) (= size block-size)]
    [(ctr)         (= size block-size)]
    [(gcm)         (<= 1 size 16)] ;; actual upper bound much higher
    [(ocb)         (<= 0 size 15)] ;; "no more than 120 bits"
    [(eax)         (<= 0 size 16)] ;; actually unrestricted
    [else #f]))

;; ============================================================
;; Stream Ciphers

(define known-stream-ciphers
  '#hasheq(;; symbol  ->  [IV  AllowedKeys ]      -- sizes in bytes
           [rc4        .  [ 0  #s(varsize 5 256 1)]]
           ;; original Salsa20 uses 64-bit nonce + 64-bit counter; IETF version uses 96/32 split instead
           [salsa20    .  [ 8  (32)]]
           [salsa20r8  .  [ 8  (32)]]
           [salsa20r12 .  [ 8  (32)]]
           [chacha20   .  [ 8  (32)]]
           [chacha20-poly1305   . [ 12 (32)]] ;; 96-bit nonce (IETF)
           ;; [chacha20-poly1305/8 . [ 8  (32)]] ;; 64-bit nonce (original)
           ))

;; stream-cipher-name? : Any -> Boolean
(define (stream-cipher-name? x)
  (and (hash-ref known-stream-ciphers x #f) #t))

;; stream-cipher-key-sizes : Symbol -> SizeSet
(define (stream-cipher-key-sizes x)
  (cond [(hash-ref known-stream-ciphers x #f) => cadr]
        [else #f]))

;; stream-cipher-aead? : Symbol -> Boolean
(define (stream-cipher-aead? x)
  (case x
    [(chacha20-poly1305 chacha20-poly1305/8) #t]
    [else #f]))

;; stream-cipher-default-auth-size : Symbol -> Nat/#f
(define (stream-cipher-default-auth-size x)
  (case x
    [(chacha20-poly1305 chachc20-poly1305/8) 16]
    [else #f]))

;; stream-cipher-default-iv-size : Symbol -> Nat/#f
(define (stream-cipher-default-iv-size cipher)
  (cond [(hash-ref known-stream-ciphers cipher #f) => car]
        [else #f]))

;; stream-cipher-iv-size-ok? : Symbol Nat -> Boolean
(define (stream-cipher-iv-size-ok? cipher size)
  (= (or (stream-cipher-default-iv-size cipher) 0) size))


;; ============================================================
;; Cipher Specs

;; A CipherSpec is one of
;;  - (list StreamCipherName 'stream)
;;  - (list BlockCipherName BlockMode)
;; BlockCipherName is a symbol in the domain of known-block-ciphers,
;; StreamCipherName is a symbol in the domain of known-stream-ciphers.

(define (cipher-spec? x)
  (match x
    [(list (? stream-cipher-name?) 'stream) #t]
    [(list (? block-cipher-name? cipher) (? block-mode? mode))
     (block-mode-block-size-ok? mode (block-cipher-block-size cipher))]
    [_ #f]))

(define (cipher-spec-mode x) (cadr x))
(define (cipher-spec-algo x) (car x))

;; ----------------------------------------

(define (cipher-spec-key-sizes cipher-spec)
  (match cipher-spec
    [(list (? stream-cipher-name? cipher-name) 'stream)
     (stream-cipher-key-sizes cipher-name)]
    [(list (? block-cipher-name? cipher-name) (? block-mode? mode))
     (block-cipher-key-sizes cipher-name)]))

(define MIN-DEFAULT-KEY-SIZE (quotient 128 8))

(define (cipher-spec-default-key-size cipher-spec)
  (define allowed (cipher-spec-key-sizes cipher-spec))
  (cond [(size-set-contains? allowed MIN-DEFAULT-KEY-SIZE)
         MIN-DEFAULT-KEY-SIZE]
        [(list? allowed)
         (or (for/or ([size (in-list allowed)] #:when (>= size MIN-DEFAULT-KEY-SIZE)) size)
             (apply max allowed))]
        [else (error 'cipher-spec-default-key-size "internal error, variable key sizes")]))

(define (cipher-spec-aead? cipher-spec)
  (match cipher-spec
    [(list (? stream-cipher-name? cipher-name) 'stream)
     (stream-cipher-aead? cipher-name)]
    [(list (? block-cipher-name? cipher-name) (? block-mode? mode))
     (block-mode-aead? mode)]))

(define (cipher-spec-default-auth-size cipher-spec)
  (match cipher-spec
    [(list (? stream-cipher-name? cipher-name) 'stream)
     (stream-cipher-default-auth-size cipher-name)]
    [(list (? block-cipher-name? cipher-name) (? block-mode? mode))
     (block-mode-default-auth-size mode)]))

(define (cipher-spec-block-size cipher-spec)
  (match cipher-spec
    [(list (? stream-cipher-name?) 'stream) 1]
    [(list (? block-cipher-name? cipher-name) (? block-mode? mode))
     (case (block-mode-type mode)
       [(stream) 1]
       [(block) (block-cipher-block-size cipher-name)])]))

(define (cipher-spec-iv-size cipher-spec)
  (match cipher-spec
    [(list (? stream-cipher-name? cipher-name) 'stream)
     (stream-cipher-default-iv-size cipher-name)]
    [(list (? block-cipher-name? cipher-name) (? block-mode? mode))
     (block-mode-default-iv-size mode (block-cipher-block-size cipher-name))]))

(define (cipher-spec-key-size-ok? cipher-spec key-size)
  (size-set-contains? (cipher-spec-key-sizes cipher-spec) key-size))

(define (check-key-size cipher-spec key-size)
  (define allowed (cipher-spec-key-sizes cipher-spec))
  (unless (size-set-contains? allowed key-size)
    (crypto-error "bad key size for cipher\n  cipher: ~e\n  given: ~e\n  allowed: ~a"
                  cipher-spec key-size
                  (match allowed
                    [(? list?) (string-join (map number->string allowed ", "))]
                    [(varsize min max step) (format "from ~a to ~a in multiples of ~a" min max step)]))))

;; cipher-spec-uses-padding? : CipherSpec -> Boolean
(define (cipher-spec-uses-padding? spec)
  (match spec
    [(list (? stream-cipher-name?) 'stream) #f]
    [(list (? block-cipher-name?) (? block-mode? mode))
     (eq? (block-mode-type mode) 'block)]))

;; ============================================================
;; PK

(define known-pk
  '#hasheq([rsa . (sign encrypt)]
           [dsa . (sign params)]
           [dh  . (key-agree params)]
           [ec  . (sign key-agree params)]))

(define (pk-spec? x)
  (and (hash-ref known-pk x #f) #t))

(define (pk-spec-can-sign? pk)
  (and (memq 'sign (hash-ref known-pk pk '())) #t))
(define (pk-spec-can-encrypt? pk)
  (and (memq 'encrypt (hash-ref known-pk pk '())) #t))
(define (pk-spec-can-key-agree? pk)
  (and (memq 'key-agree (hash-ref known-pk pk '())) #t))
(define (pk-spec-has-parameters? pk)
  (and (memq 'params (hash-ref known-pk pk '())) #t))

;; ============================================================
;; KDF

(define (kdf-spec? x)
  (match x
    ['bcrypt #t]
    ['scrypt #t]
    [(list 'pbkdf2 'hmac di)
     (digest-spec? di)]
    [_ #f]))
