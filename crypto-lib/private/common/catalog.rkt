;; Copyright 2013-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/list
         racket/class
         "error.rkt")
(provide (all-defined-out))

;; Security Strength
;; Reference: NIST 800-57 Part 1 Section 5.6
;; SecurityStrength = (U #f Nat), #f is unknown, 0 if known insecure.

;; Conventions:
;; - "size" is number of bytes

;; ============================================================
;; Info

(define info<%>
  (interface ()
    get-spec
    ))

;; ============================================================
;; Digests

(define digest-info<%>
  (interface (info<%>)
    ;; get-spec     ;; -> DigestSpec
    get-size        ;; -> (U Nat #f) -- #f for var/XOF
    get-size*       ;; -> (U Nat 'var 'xof)
    get-block-size  ;; -> Nat
    has-config?     ;; -> Boolean
    get-key-sizes   ;; -> SizeSet
    key-size-ok?    ;; Nat -> Boolean
    get-security-strength ;; Boolean -> (U #f Nat)
    ))

(define digest-info%
  (class* object% (digest-info<%>)
    (init-field spec size block-size config? key-sizes ci-secbits cr-secbits)
    (super-new)
    (define/public (get-spec) spec)
    (define/public (get-size) (and (exact-integer? size) size))
    (define/public (get-size*) size)
    (define/public (get-block-size) block-size)
    (define/public (has-config?) config?)
    (define/public (get-key-sizes) key-sizes)
    (define/public (key-size-ok? keysize)
      (size-set-contains? key-sizes keysize))

    ;; get-security-strength : Boolean -> (U #f Nat)
    ;; cr? indicates whether collision-resistance is needed
    (define/public (get-security-strength cr?)
      (cond [cr? cr-secbits] [else ci-secbits]))
    ))

(define (dinfo spec size block-size
               [ci-secbits #f]
               [cr-secbits (and ci-secbits (quotient ci-secbits 2))]
               #:k [key-size #f] #:ks [key-sizes '(0)] #:c? [config? #f])
  ;; FIXME: key-size unused
  (new digest-info% (spec spec) (size size) (block-size block-size) (config? config?)
       (cr-secbits cr-secbits) (ci-secbits ci-secbits) (key-sizes key-sizes)))

(define (get-simple-digest-infos)
  (list (dinfo 'md2         16  16   0)
        (dinfo 'md4         16  64   0)
        (dinfo 'md5         16  64   0)
        (dinfo 'ripemd160   20  64   #f)
        (dinfo 'tiger1      24  64   #f)
        (dinfo 'tiger2      24  64   #f)
        (dinfo 'whirlpool   64  64   #f) ;; Note: 3 versions, W-0 (2000), W-T (2001), W (2003)
        (dinfo 'sha0        20  64   0)
        (dinfo 'sha1        20  64   128 0)
        (dinfo 'sha224      28  64   224)
        (dinfo 'sha256      32  64   256)
        (dinfo 'sha384      48  128  384)
        (dinfo 'sha512      64  128  512)
        (dinfo 'sha512/224  28  128  224)
        (dinfo 'sha512/256  32  128  256)
        (dinfo 'sha3-224    28  144  224)
        (dinfo 'sha3-256    32  136  256)
        (dinfo 'sha3-384    48  104  384)
        (dinfo 'sha3-512    64  72   512)
        ;; blake2b: out[1..64], key[0..64], salt[16], personalization[16]
        ;; blake2s: out[1..32], key[0..32], salt[8], personalization[8]
        (dinfo 'blake2b   'var  128  #f  #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-512 64  128  512 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-384 48  128  384 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-256 32  128  256 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-160 20  128  160 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2s   'var  64   #f  #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-256 32  64   256 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-224 28  64   224 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-160 20  64   160 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-128 16  64   128 #:c? #t #:ks '#s(varsize 0 32 1))
        ;; the following are XOFs (extensible output functions)
        (dinfo 'shake128  'xof  168  128 128)
        (dinfo 'shake256  'xof  136  256 256)
        ;; cshake: out[0..], N=function[0..], S=customization[0..]
        (dinfo 'cshake128 'xof  168  128 128 #:c? #t)
        (dinfo 'cshake256 'xof  136  256 256 #:c? #t)
        ))

(define known-digests
  (for/hasheq ([di (in-list (get-simple-digest-infos))])
    (values (send di get-spec) di)))

;; A DigestSpec is a symbol in domain of known-digests.

(define (digest-spec? x)
  (and (symbol? x) (hash-ref known-digests x #f) #t))

(define (digest-spec->info dspec [err? #f])
  (or (hash-ref known-digests dspec #f)
      (if err? (crypto-error "bad digest spec: ~e" dspec) #f)))

(define (digest-spec-size ds)
  (send (digest-spec->info ds #t) get-size))
(define (digest-spec-block-size ds)
  (send (digest-spec->info ds #t) get-block-size))
(define (digest-spec-security-strength ds [cr? #t])
  (send (digest-spec->info ds #t) get-security-strength cr?))

(define (list-known-digests)
  (sort (hash-keys known-digests) symbol<?))

;; ----------------------------------------
;; MACs

;; MAC specs are distinct from digest-spec, except overlap for blake2[bs].
;; MAC info represented using digest-info%, but not interned.

(define (mac-spec? x)
  (match x
    [(? symbol?) (and (memq x '(blake2b blake2s kmac128 kmac256 poly1305)) #t)]
    [(list 'hmac (? digest-spec?)) #t]
    [(list 'cmac (? block-cipher-name?)) #t]
    [(list 'gmac (? block-cipher-name? bcname))
     (let ([bci (block-cipher-name->info bcname)])
       (and bci (= (send bci get-block-size) 16)))]
    [_ #f]))

(define (mac-spec->info spec)
  (match spec
    [(or 'blake2b 'blake2s)
     (digest-spec->info spec)]
    ['kmac128
     (dinfo spec 16 168 #:ks '#s(varsize 0 +inf.0 1))]
    ['kmac256
     (dinfo spec 32 136 #:ks '#s(varsize 0 +inf.0 1))]
    ['poly1305
     (dinfo spec 32 16 #:ks '(32))]
    [(list 'hmac (? digest-spec? dspec))
     (define di (digest-spec->info dspec))
     (define any-sizes '#s(varsize 1 +inf.0 1))
     (define dsize (send di get-size))
     (dinfo spec dsize (send di get-block-size) #:k dsize #:ks any-sizes)]
    [(list 'cmac (? block-cipher-name? bcname))
     (define bci (block-cipher-name->info bcname))
     (define block-size (send bci get-block-size))
     (define key-sizes (send bci get-key-sizes))
     (define key-size (size-set-default key-sizes DEFAULT-KEY-SIZE))
     (dinfo spec block-size block-size #:k key-size #:ks key-sizes)]
    [(list 'gmac (? block-cipher-name? bcname))
     (define bci (block-cipher-name->info bcname))
     (cond [(= (send bci get-block-size) 16)
            (define key-sizes (send bci get-key-sizes))
            (define key-size (size-set-default key-sizes DEFAULT-KEY-SIZE))
            (dinfo spec 16 16 #:k key-size #:ks key-sizes)]
           [else #f])]
    [_ #f]))

(define (list-known-mac-specs)
  (define (mspec<? a b)
    (cond [(and (symbol? a) (symbol? b))
           (symbol<? a b)]
          [(symbol? a) #t]
          [(symbol? b) #f]
          [(symbol<? (car a) (car b)) #t]
          [(eq? (car a) (car b))
           (symbol<? (cadr a) (cadr b))]
          [else #f]))
  (define specs
    (append
     '(blake2b blake2s kmac128 kmac256 poly1305)
     ;; exclude UMAC -- only one impl (nettle)
     (for/list ([(dspec di) (in-hash known-digests)]
                #:when (send di get-size))
       `(hmac ,dspec))
     (for/list ([(bcname bci) (in-hash known-block-ciphers)])
       `(cmac ,bcname))
     (for/list ([(bcname bci) (in-hash known-block-ciphers)]
                #:when (= (send bci get-block-size) 16))
       `(gmac ,bcname))))
  (sort specs mspec<?))

;; ============================================================

;; SizeSet is either (Listof Nat) or VarSizeSet
;; VarSizeSet is (varsize Nat Nat Nat)
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
  (interface (info<%>)
    ;; get-spec     ;; -> CipherSpec
    get-cipher-name ;; -> Symbol
    get-mode        ;; -> (U BlockMode 'stream)
    get-type        ;; -> (U 'block 'stream)
    aead?           ;; -> Boolean
    get-block-size  ;; -> Nat  -- 1 for stream cipher
    get-chunk-size  ;; -> Nat  -- natural processing unit (eg, underlying block size)
    get-key-size    ;; -> Nat
    get-key-sizes   ;; -> SizeSet
    key-size-ok?    ;; Nat -> Boolean
    get-iv-size     ;; -> Nat
    iv-size-ok?     ;; Nat -> Boolean
    get-auth-size   ;; -> Nat  -- 0 if not AEAD
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
        [else (internal-error "unknown block mode: ~e" mode)]))
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
            (info 'chacha20-poly1305/iv8 64  8  '(32) 16) ;; 64-bit nonce (original)
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

(define (list-known-ciphers)
  (append (for*/list ([cipher (in-list (sort (hash-keys known-block-ciphers) symbol<?))]
                      [mode (sort known-block-modes symbol<?)]
                      [spec (in-value (list cipher mode))]
                      #:when (cipher-spec? spec))
            spec)
          (for/list ([cipher (in-list (sort (hash-keys known-stream-ciphers) symbol<?))])
            (list cipher 'stream))))

;; ============================================================
;; PK

(define pk-info<%>
  (interface (info<%>)
    ;; get-spec     ;; -> PKSpec
    can-sign?       ;; (U Pad #f) (U DigestSpec #f) -> Boolean
    can-encrypt?    ;; (U Pad #f) -> Boolean
    can-key-agree?  ;; -> Boolean
    has-params?     ;; -> Boolean
    ;; for can-{sign,encrypt}?: pad=#f means "at all?"
    ))

(define pk-info%
  (class* object% (pk-info<%>)
    (init-field spec)
    (super-new)
    (define/public (get-spec) spec)
    (define/public (can-sign? pad dspec)
      (case spec
        [(rsa)      ;; impl must check digest
         (and (memq pad '(pkcs1-v1.5 pss pss* #f)) #t)]
        [(dsa ec)   ;; digest ignored for backwards compatibility
         (and (memq pad '(#f)) #t)]
        [(eddsa)    ;; digest must be 'none (future might use digest to mean EdDSAph)
         (and (memq pad '(#f)) (memq dspec '(#f none)) #t)]
        [else #f]))
    (define/public (can-encrypt? pad)
      (case spec
        [(rsa) (and (memq pad '(pkcs1-v1.5 oaep #f)) #t)]
        [else #f]))
    (define/public (can-key-agree?)
      (and (memq spec '(dh ec ecx)) #t))
    (define/public (has-params?)
      (and (memq spec '(dsa dh ec eddsa ecx)) #t))
    ))

(define (list-known-pks)
  '(rsa dsa dh ec eddsa ecx))

(define known-pk
  (for/hasheq ([pk (in-list (list-known-pks))])
    (values pk (new pk-info% (spec pk)))))

(define (pk-spec? x)
  (and (memq x (list-known-pks)) #t))

(define (pk-spec->info pk)
  (hash-ref known-pk pk #f))

;; ----------------------------------------
;; Elliptic Curve information

;; alias->curve-name : (U String Symbol) -> Symbol
;; Return the canonical (for this library) name of a curve.
(define (alias->curve-name x)
  (car (curve-name->aliases x)))

;; curve-name->aliases : (U String Symbol) -> (NEListof Symbol)
(define (curve-name->aliases x)
  (cond [(string? x) (curve-name->aliases (string->symbol x))]
        [(for/or ([e (in-list curve-aliases)] #:when (memq x e)) e) => values]
        [else (list x)]))

;; curve-aliases : (Listof (NonEmptyListof Symbol))
;; This library regards the first entry in each list as the canonical name.
(define curve-aliases
  ;; Reference: https://tools.ietf.org/html/rfc4492#appendix-A
  ;; [ SEC2/RFC4492 | NIST FIPS 186-4 | ANSI X9.62 ]
  '([sect163k1 |NIST K-163|]
    [sect163r2 |NIST B-163|]
    [sect233k1 |NIST K-233|]
    [sect233r1 |NIST B-233|]
    [sect283k1 |NIST K-283|]
    [sect283r1 |NIST B-283|]
    [sect409k1 |NIST K-409|]
    [sect409r1 |NIST B-409|]
    [sect571k1 |NIST K-571|]
    [sect571r1 |NIST B-571|]
    [secp192r1 |NIST P-192| prime192v1]
    [secp224r1 |NIST P-224|]
    [secp256r1 |NIST P-256| prime256v1]
    [secp384r1 |NIST P-384|]
    [secp521r1 |NIST P-521|]))

;; The following functions return 0 for invalid curve names, so the
;; result can be passed to make-bytes before the curve is checked.

;; ed-curve->key-size : Symbol -> Nat
;; Size of secret key and public key.
(define (ed-curve->key-size curve)
  (case curve
    [(ed25519) 32]
    [(ed448)   57]
    [else 0]))

;; ed-curve->sig-size : Symbol -> Nat
;; Size of signature.
(define (ed-curve->sig-size curve)
  (case curve
    [(ed25519) 64]
    [(ed448)  114]
    [else 0]))

;; ecx-curve->key-size : Symbol -> Nat
;; Size of secret key, public key, and shared secret.
(define (ecx-curve->key-size curve)
  (case curve
    [(x25519) 32]
    [(x448)   56]
    [else 0]))

;; ============================================================
;; KDF

;; KDF info objects are not interned.

(define kdf-info<%>
  (interface (info<%>)
    get-salt-mode     ;; -> (U 'req 'opt #f)
    get-salt-default  ;; -> (U Bytes #f), only if mode='opt
    ))

(define kdf-info%
  (class* object% (kdf-info<%>)
    (init-field spec salt-mode salt-default)
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-salt-mode) salt-mode)
    (define/public (get-salt-default) salt-default)
    ))

(define (list-known-simple-kdfs)
  '(argon2d argon2i argon2id scrypt))

(define (kdf-spec? x)
  (match x
    [(? symbol?)
     (and (memq x (list-known-simple-kdfs)) #t)]
    [(list 'pbkdf2 'hmac di)
     (digest-spec? di)]
    [(list 'hkdf di)
     (digest-spec? di)]
    [(list 'concat di)
     (digest-spec? di)]
    [(list 'concat 'hmac di)
     (digest-spec? di)]
    [(list 'ans-x9.63 di)
     (digest-spec? di)]
    [(list 'sp800-108-counter 'hmac di)
     (digest-spec? di)]
    [(list 'sp800-108-feedback 'hmac di)
     (digest-spec? di)]
    [(list 'sp800-108-double-pipeline 'hmac di)
     (digest-spec? di)]
    [_ #f]))

(define (kdf-spec->info spec)
  (define (make-info salt-mode [salt-default #f])
    (new kdf-info% (spec spec) (salt-mode salt-mode) (salt-default salt-default)))
  (match spec
    [(? symbol?)
     (and (memq spec (list-known-simple-kdfs)) (make-info 'req))]
    [`(pbkdf2 hmac ,(? digest-spec? dspec))
     (make-info 'req)]
    [`(hkdf ,(? digest-spec? dspec))
     ;; HKDF RFC says if salt absent, set to zeros of length hash *output*
     (define salt (make-bytes (digest-spec-size dspec) 0))
     (make-info 'opt (bytes->immutable-bytes salt))]
    [`(concat ,(? digest-spec? dspec))
     (make-info #f)]
    [`(concat hmac ,(? digest-spec? dspec))
     ;; SP800-56Cr2 says if salt absent, set to zeros of length hash *block*
     (define salt (make-bytes (digest-spec-block-size dspec) 0))
     (make-info 'opt (bytes->immutable-bytes salt))]
    [`(ans-x9.63 ,(? digest-spec? dspec))
     (make-info #f)]
    [`(sp800-108-counter hmac ,(? digest-spec? dspec))
     (make-info #f)]
    [`(sp800-108-feedback hmac ,(? digest-spec? dspec))
     (make-info 'req)]
    [`(sp800-108-double-pipeline hmac ,(? digest-spec? dspec))
     (make-info #f)]
    [_ #f]))

;; list-known-kdfs : -> (Listof KDFSpec)
(define (list-known-kdfs)
  (append (list-known-simple-kdfs)
          (for/list ([di (in-list (list-known-digests))])
            `(pbkdf2 hmac ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(hkdf ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(concat ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(concat hmac ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(concat hmac ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(ans-x9.63 ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(sp800-108-counter hmac ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(sp800-108-feedback hmac ,di))
          (for/list ([di (in-list (list-known-digests))])
            `(sp800-108-double-pipeline hmac ,di))
          ))
