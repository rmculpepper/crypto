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
         racket/class
         "error.rkt")
(provide (all-defined-out))

;; ============================================================
;; Digests

(define digest-info<%>
  (interface ()
    get-spec        ;; -> DigestSpec
    get-size        ;; -> Nat
    get-block-size  ;; -> Nat
    ))

(define digest-info%
  (class* object% (digest-info<%>)
    (init-field spec size block-size max-key-len)
    (super-new)
    (define/public (get-spec) spec)
    (define/public (get-size) size)
    (define/public (get-block-size) block-size)
    (define/public (get-max-key-len) max-key-len)))

(define known-digests
  (let ()
    (define (info spec size block-size [max-key-len #f])
      (new digest-info% (spec spec) (size size) (block-size block-size) (max-key-len max-key-len)))
    (define all
      (list (info 'md2         16  16)
            (info 'md4         16  64)
            (info 'md5         16  64)
            (info 'ripemd160   20  64)
            (info 'tiger1      24  64)
            (info 'tiger2      24  64)
            (info 'whirlpool   64  64) ;; Note: 3 versions, W-0 (2000), W-T (2001), W (2003)
            (info 'sha0        20  64)
            (info 'sha1        20  64)
            (info 'sha224      28  64)
            (info 'sha256      32  64)
            (info 'sha384      48  128)
            (info 'sha512      64  128)
            (info 'sha3-224    28  144)
            (info 'sha3-256    32  136)
            (info 'sha3-384    48  104)
            (info 'sha3-512    64  72)
            ;; the following take keys
            (info 'blake2b-512 64  128  64) ;; blake2b up to 64 bytes
            (info 'blake2b-384 48  128  64)
            (info 'blake2b-256 32  128  64)
            (info 'blake2b-160 20  128  64)
            (info 'blake2s-256 32  64   32) ;; blake2s up to 32 bytes
            (info 'blake2s-224 28  64   32)
            (info 'blake2s-160 20  64   32)
            (info 'blake2s-128 16  64   32)
            ;; the following are XOFs (extensible output functions) -- put #f for output size
            (info 'shake128    #f  168)
            (info 'shake256    #f  136)))
    (for/hasheq ([di (in-list all)])
      (values (send di get-spec) di))))

;; A DigestSpec is a symbol in domain of known-digests.

(define (digest-spec? x)
  (and (symbol? x) (hash-ref known-digests x #f) #t))

(define (digest-spec->info di)
  (hash-ref known-digests di #f))

(define (digest-spec-size ds)
  (send (digest-spec->info ds) get-size))
(define (digest-spec-block-size ds)
  (send (digest-spec->info ds) get-block-size))

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

(define (size-set-default ss dmin)
  (if (size-set-contains? ss dmin)
      dmin
      (match ss
        [(? list? ss)
         (or (for/or ([n (in-list ss)] #:when (>= n dmin)) n)
             (apply max ss))]
        [(varsize min max step)
         (or (for/or ([n (in-range min (add1 max) step)] #:when (>= n dmin)) n)
             max)])))

;; ============================================================
;; Cipher Info

(define cipher-info<%>
  (interface ()
    get-cipher-name ;; -> Symbol
    get-mode        ;; -> (U BlockMode 'stream)
    get-spec        ;; -> CipherSpec
    get-type        ;; -> (U 'block 'stream)
    aead?           ;; -> Boolean
    get-block-size  ;; -> Nat  -- 1 for stream cipher
    get-chunk-size  ;; -> Nat
    get-key-size    ;; -> Nat
    get-key-sizes   ;; -> SizeSet
    key-size-ok?    ;; Nat -> Boolean
    get-iv-size     ;; -> Nat
    iv-size-ok?     ;; Nat -> Boolean
    get-auth-size   ;; -> SizeSet
    auth-size-ok?   ;; Nat -> Boolean
    uses-padding?   ;; -> Boolean
    ))

(define DEFAULT-KEY-SIZE 16) ;; 128 bits

;; ============================================================
;; Block Ciphers and Modes

(define block-cipher-info%
  (class* object% (cipher-info<%>)
    (init-field bci mode)
    (super-new)
    (define spec (list (get-cipher-name) (get-mode)))
    (define/public (get-cipher-name) (send bci get-name))
    (define/public (get-mode) mode)
    (define/public (get-spec) spec)
    (define/public (get-type)
      (case mode
        [(ecb cbc) 'block]
        [(ofb cfb ctr gcm ocb eax) 'stream]))
    (define/public (aead?)
      (positive? (get-auth-size)))
    (define/public (get-block-size)
      (case (get-type) [(stream) 1] [else (send bci get-block-size)]))
    (define/public (get-chunk-size) (send bci get-block-size))
    (define/public (get-key-size) (size-set-default (get-key-sizes) DEFAULT-KEY-SIZE))
    (define/public (get-key-sizes) (send bci get-key-sizes))
    (define/public (key-size-ok? size) (send bci key-size-ok? size))
    (define/public (get-iv-size)
      (case mode
        [(ecb)             0]
        [(cbc ofb cfb ctr) (get-chunk-size)]
        [(gcm ocb eax)     12]
        [else (crypto-error "internal error, unknown block mode: ~e" mode)]))
    (define/public (iv-size-ok? size)
      (case mode
        [(ecb)         (= size 0)]
        [(cbc ofb cfb) (= size (get-chunk-size))]
        [(ctr)         (= size (get-chunk-size))]
        [(gcm)         (<= 1 size 16)] ;; actual upper bound much higher
        [(ocb)         (<= 0 size 15)] ;; "no more than 120 bits"
        [(eax)         (<= 0 size 16)] ;; actually unrestricted
        [else #f]))
    (define/public (get-auth-size)
      (case mode [(gcm ocb eax) 16] [else 0]))
    (define/public (auth-size-ok? size)
      (case mode
        [(gcm) (or (<= 12 size 16) (= size 8) (= size 4))]
        [(ocb eax) (<= 1 size 16)]
        [else (= size 0)]))
    (define/public (uses-padding?) (eq? (get-type) 'block))
    ))

;; ----------------------------------------

(define block-algo-info<%>
  (interface ()
    get-name        ;; -> Symbol
    get-block-size  ;; -> Nat
    get-key-sizes   ;; -> SizeSet
    key-size-ok?    ;; Nat -> Boolean
    mode-ok?        ;; BlockMode -> Boolean
    ))

(define block-algo-info%
  (class* object% (block-algo-info<%>)
    (init-field name block-size key-sizes)
    (super-new)
    (define/public (get-name) name)
    (define/public (get-block-size) block-size)
    (define/public (get-key-sizes) key-sizes)
    (define/public (key-size-ok? size) (size-set-contains? key-sizes size))
    (define/public (mode-ok? mode) (block-mode-block-size-ok? mode block-size))))

(define known-block-ciphers
  (let ()
    (define (info name block-size key-sizes)
      (new block-algo-info% (name name) (block-size block-size) (key-sizes key-sizes)))
    (define all
      (list (info 'aes      16   '(16 24 32))
            (info 'des       8   '(8))      ;; key 8 bytes w/ parity bits
            (info 'des-ede2  8   '(16))     ;; key 16 bytes w/ parity bits
            (info 'des-ede3  8   '(24))     ;; key 24 bytes w/ parity bits
            (info 'blowfish  8   '#s(varsize 4 56 1))
            (info 'cast128   8   '#s(varsize 5 16 1))
            (info 'camellia 16   '(16 24 32))
            (info 'serpent  16   '#s(varsize 0 32 1))
            (info 'twofish  16   '#s(varsize 8 32 1))
            (info 'idea      8   '(16))
            #|
            (info 'rc5       8   '#s(varsize 0 255 1))
            (info 'rc5-64   16   '#s(varsize 0 255 1))
            (info 'rc6-64   32   '#s(varsize 0 255 1))
            (info 'cast256  16   '#s(varsize 16 32 4))
            (info 'rc6      16   '#s(varsize 0 255 1))
            (info 'mars     16   '#s(varsize 16 56 4)) ;; aka Mars-2 ???
            |#))
    (for/hasheq ([bci (in-list all)])
      (values (send bci get-name) bci))))

;; block-cipher-name? : Any -> Boolean
(define (block-cipher-name? x)
  (and (hash-ref known-block-ciphers x #f) #t))

(define (block-cipher-name->info name)
  (hash-ref known-block-ciphers name #f))

;; ----------------------------------------

;; Block modes are complicated; some modes are defined only for
;; 128-bit block ciphers; others have variable-length IVs/nonces or
;; authentication tags.

(define known-block-modes '(ecb cbc ofb cfb ctr gcm ocb eax))

;; block-mode? : Any -> Boolean
(define (block-mode? x)
  (and (memq x known-block-modes) #t))

;; block-mode-block-size-ok? : Symbol Nat -> Boolean
;; Is the block mode compatible with ciphers of the given block size?
(define (block-mode-block-size-ok? mode block-size)
  (case mode
    ;; EAX claims to be block-size agnostic, but nettle restricts to 128-bit block ciphers
    [(gcm ocb eax) (= block-size 16)]
    [else #t]))

;; ============================================================
;; Stream Ciphers

(define stream-cipher-info%
  (class* object% (cipher-info<%>)
    (init-field name chunk-size ivlen key-sizes auth-len)
    (super-new)
    (define/public (get-cipher-name) name)
    (define/public (get-mode) 'stream)
    (define/public (get-spec) (list (get-cipher-name) 'stream))
    (define/public (get-type) 'stream)
    (define/public (aead?) (positive? (get-auth-size)))
    (define/public (get-block-size) 1)
    (define/public (get-chunk-size) chunk-size)
    (define/public (get-key-size) (size-set-default key-sizes DEFAULT-KEY-SIZE))
    (define/public (get-key-sizes) key-sizes)
    (define/public (key-size-ok? size) (size-set-contains? key-sizes size))
    (define/public (get-iv-size) ivlen)
    (define/public (iv-size-ok? size) (= size ivlen))
    (define/public (get-auth-size) auth-len)
    (define/public (auth-size-ok? size) (= size (get-auth-size)))
    (define/public (uses-padding?) #f)))

(define known-stream-ciphers
  (let ()
    (define (info name chunk-size ivlen key-sizes auth-len)
      (new stream-cipher-info% (name name) (chunk-size chunk-size) (ivlen ivlen)
           (key-sizes key-sizes) (auth-len auth-len)))
    (define all
      (list (info 'rc4                    1  0  '#s(varsize 5 256 1) 0)
            ;; original Salsa20 uses 64-bit nonce + 64-bit counter; IETF version uses 96/32 split instead
            (info 'salsa20               64  8  '(32) 0)
            (info 'salsa20r8             64  8  '(32) 0)
            (info 'salsa20r12            64  8  '(32) 0)
            (info 'chacha20              64  8  '(32) 0)
            (info 'chacha20-poly1305     64 12  '(32) 16) ;; 96-bit nonce (IETF)
            (info 'chacha20-poly1305/8   64  8  '(32) 16) ;; 64-bit nonce (original)
            (info 'xchacha20-poly1305    64 24  '(32) 16)))
    (for/hasheq ([sci (in-list all)])
      (values (send sci get-cipher-name) sci))))

;; stream-cipher-name? : Any -> Boolean
(define (stream-cipher-name? x)
  (and (hash-ref known-stream-ciphers x #f) #t))

(define (stream-cipher-name->info x)
  (hash-ref known-stream-ciphers x #f))

;; ============================================================
;; Cipher Specs

;; A CipherSpec is one of
;;  - (list StreamCipherName 'stream)
;;  - (list BlockCipherName BlockMode)
;; BlockCipherName is a symbol in the domain of known-block-ciphers,
;; StreamCipherName is a symbol in the domain of known-stream-ciphers.

(define (cipher-spec? x)
  (and (pair? x) (cipher-spec->info x) #t))

(define (cipher-spec-mode x) (cadr x))
(define (cipher-spec-algo x) (car x))

;; cipher-spec-table : Hash[ CipherSpec => CipherInfo ]
(define cipher-spec-table (make-weak-hash))

(define (cipher-spec->info spec)
  (define (get-info)
    (match spec
      [(list (? symbol? cipher) 'stream)
       (stream-cipher-name->info cipher)]
      [(list (? symbol? cipher) (? block-mode? mode))
       (define bci (block-cipher-name->info cipher))
       (and bci (send bci mode-ok? mode)
            (new block-cipher-info% (bci bci) (mode mode)))]
      [_ #f]))
  (cond [(hash-ref cipher-spec-table spec #f) => values]
        [(get-info) => (lambda (ci) (hash-set! cipher-spec-table (send ci get-spec) ci) ci)]
        [else #f]))

;; ============================================================
;; PK

(define known-pk
  '#hasheq([rsa . (sign encrypt)]
           [dsa . (sign params)]
           [dh  . (key-agree params)]
           [ec  . (sign key-agree params)]))
(define rsa-sign-pads '(pkcs1-v1.5 pss pss* #f))
(define rsa-enc-pads '(pkcs1-v1.5 oeap #f))

(define (pk-spec? x)
  (and (hash-ref known-pk x #f) #t))

;; for can-sign?, can-encrypt?: pad=#f means "at all?"
(define (pk-spec-can-sign? pk pad)
  (case pk
    [(rsa)    (and (memq pad rsa-sign-pads) #t)]
    [(dsa ec) (and (memq pad '(#f)) #t)]
    [else #f]))
(define (pk-spec-can-encrypt? pk pad)
  (case pk
    [(rsa) (and (memq pad rsa-enc-pads) #t)]
    [else #f]))

(define (pk-spec-can-key-agree? pk)
  (and (memq 'key-agree (hash-ref known-pk pk '())) #t))
(define (pk-spec-has-parameters? pk)
  (and (memq 'params (hash-ref known-pk pk '())) #t))

;; ============================================================
;; KDF

(define (kdf-spec? x)
  (match x
    [(? symbol?) (and (memq x '(bcrypt scrypt argon2d argon2i argon2id)) #t)]
    [(list 'pbkdf2 'hmac di)
     (digest-spec? di)]
    [_ #f]))
