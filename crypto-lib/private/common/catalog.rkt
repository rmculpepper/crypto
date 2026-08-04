;; Copyright 2013-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/contract/base
         racket/list
         scramble/bundle
         scramble/struct
         "error.rkt")
(provide (all-defined-out))

;; Security Strength
;; Reference: NIST 800-57 Part 1 Section 5.6
;; SecurityStrength = (U #f Nat), #f is unknown, 0 if known insecure.

;; Conventions:
;; - "size" is number of bytes

;; ============================================================

(define nat? exact-nonnegative-integer?)

(define-interface simple-write$
  ([to-write-string (-> simple-write$? string?)]
   [to-write-prefixes (-> simple-write$? (listof string?))])
  #:fallbacks
  (hasheq 'to-write-prefixes (lambda (self) null))
  #:derive-property prop:custom-write
  (lambda (self out mode)
    (define prefixes ($to-write-prefixes self))
    (fprintf out "#<~a~a>"
             (apply string-append
                    (for/list ([prefix (in-list prefixes)])
                      (format "~a:" prefix)))
             ($to-write-string self)))
  #:generics-prefix $)

#;
(define-interface custom-write$
  (custom-write ;; X OutputPort Mode -> Void
   )
  #:derive-property prop:custom-write
  (lambda (self out mode) ($custom-write self out mode))
  #:generics-prefix $)

;; ============================================================

;; SizeSet is either (Listof Nat) or VarSizeSet
;; VarSizeSet is (varsize Nat Nat Nat)
(struct varsize (min max step) #:prefab)

(define size-set/c (or/c varsize? (listof nat?)))

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
;; Info

(define-interface has-spec$
  #:predicate has-spec?
  (get-spec)
  #:generics-prefix $)

(define-interface info$
  #:super (has-spec$)
  #:predicate info?
  ())

;; ============================================================
;; Digests

(define-interface digest-info$
  #:super (info$)
  #:predicate digest-info?
  (;; get-spec        ;; -> digest-spec?
   [di-size           (-> digest-info? (or/c nat? #f))] ;; #f for var/xof
   [di-size*          (-> digest-info? (or/c nat? 'va 'vz))]
   [di-block-size     (-> digest-info? nat?)]
   [di-has-config?    (-> digest-info? boolean?)]
   [di-config-family  (-> digest-info? (or/c symbol? #f))]
   [di-key-sizes      (-> digest-info? size-set/c)]
   [di-key-size-ok?   (-> digest-info? nat? boolean?)]
   [di-security-strength  (-> digest-info? boolean? (or/c #f nat?))])
  ;; size 'va = variable, required early (before processing); 'vz = required late
  #:fallbacks
  (let ()
    (define (di-size self)
      (let ([size ($di-size self)])
        (and (exact-integer? size) size)))
    (define (di-config-family self)
      (case ($get-spec self)
        [(cshake128 cshake256) 'cshake]
        [(blake2b blake2b-512 blake2b-384 blake2b-256 blake2b-160) 'blake2b]
        [(blake2s blake2s-256 blake2s-224 blake2s-160 blake2s-128) 'blake2s]
        [else #f]))
    (define (di-key-size-ok? self keysize)
      (size-set-contains? ($di-key-sizes self) keysize))
    (hasheq 'di-size di-size
            'di-config-family di-config-family
            'di-key-size-ok? di-key-size-ok?))
  #:generics-prefix $)

(struct info:digest
  (spec size block-size config? key-sizes ci-secbits cr-secbits)
  #:properties
  (method-properties
   #:export ([digest-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:digest)
   ;; ----
   (define (%get-spec self) (.spec self))
   ;; ----
   (define (%di-size* self) (.size self))
   (define (%di-block-size self) (.block-size self))
   (define (%di-has-config? self) (.config? self))
   (define (%di-key-sizes self) (.key-sizes self))
   (define (%di-security-strength self cr?)
     (cond [cr? (.cr-secbits self)]
           [else (.ci-secbits self)]))
   ;; ----
   (define (%to-write-string self)
     (format "info:digest:~s" (.spec self))))
  #:property prop:auto-equal+hash (list (struct-field-index spec)))

(define (dinfo spec size block-size
               [ci-secbits #f]
               [cr-secbits (and ci-secbits (quotient ci-secbits 2))]
               #:k [key-size #f] #:ks [key-sizes '(0)] #:c? [config? #f])
  (info:digest spec size block-size config? key-sizes cr-secbits ci-secbits))

;; A DigestSpec is one of
;; - SimpleDigestSpec
;; - (list 'cmac BlockCipherName)
;; - (list 'gmac BlockCipherName)   -- where cipher block size is 16
;; - (list 'hmac SimpleDigestSpec)  -- where inner is fixed-size, no key req

(define (digest-spec? x)
  (if (symbol? x)
      (simple-digest-spec? x)
      (complex-digest-spec? x)))

(define (digest-spec->info dspec [err? #f])
  (if (symbol? dspec)
      (simple-digest-spec->info dspec err?)
      (complex-digest-spec->info dspec err?)))

(define (list-known-digests)
  (append (list-simple-digest-specs)
          (list-complex-digest-specs)))

;; ----------------------------------------

;; A BasicDigestSpec is a Symbol in the list below. A "basic" digest is a
;; fixed-size, no-key digest that can be used in HMAC etc.

(define (list-basic-digest-specs)
  '(sha0
    sha1
    sha224 sha256 sha384 sha512 sha512/224 sha512/256
    sha3-224 sha3-256 sha3-384 sha3-512
    blake2b-512 blake2b-384 blake2b-256 blake2b-160
    blake2s-256 blake2s-224 blake2s-160 blake2s-128
    md2 md4 md5 ripemd160 tiger1 tiger2 whirlpool))

(define (basic-digest-spec? x)
  (and (symbol? x) (memq x (list-basic-digest-specs))))

;; A SimpleDigestSpec is a Symbol in domain of known-simple-digests.

(define (simple-digest-spec? x)
  (and (symbol? x) (hash-ref known-simple-digests x #f) #t))

(define (simple-digest-spec->info dspec [err? #f])
  (or (hash-ref known-simple-digests dspec #f)
      (if err? (crypto-error "bad digest spec: ~e" dspec) #f)))

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
        (dinfo 'blake2b    'va  128  #f  #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-512 64  128  512 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-384 48  128  384 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-256 32  128  256 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2b-160 20  128  160 #:c? #t #:ks '#s(varsize 0 64 1))
        (dinfo 'blake2s    'va  64   #f  #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-256 32  64   256 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-224 28  64   224 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-160 20  64   160 #:c? #t #:ks '#s(varsize 0 32 1))
        (dinfo 'blake2s-128 16  64   128 #:c? #t #:ks '#s(varsize 0 32 1))
        ;; the following are XOFs (extensible output functions)
        (dinfo 'shake128   'vz  168  128 128)
        (dinfo 'shake256   'vz  136  256 256)
        ;; cshake: out[0..], N=function[0..], S=customization[0..]
        (dinfo 'cshake128  'vz  168  128 128 #:c? #t)
        (dinfo 'cshake256  'vz  136  256 256 #:c? #t)
        ;; MAC algorithms
        (dinfo 'kmac128    'vz  168  128 128 #:c? #t #:ks '#s(varsize 0 +inf.0 1))
        (dinfo 'kmac256    'vz  136  256 256 #:c? #t #:ks '#s(varsize 0 +inf.0 1))
        (dinfo 'poly1305    32  16   #f      #:ks '(32))
        ))

(define known-simple-digests
  (for/hasheq ([di (in-list (get-simple-digest-infos))])
    (values ($get-spec di) di)))

(begin
  (define (digest-spec-size ds)
    ($di-size (digest-spec->info ds #t)))
  (define (digest-spec-block-size ds)
    ($di-block-size (digest-spec->info ds #t)))
  (define (digest-spec-security-strength ds [cr? #t])
    ($di-security-strength (digest-spec->info ds #t) cr?)))

(define (list-simple-digest-specs)
  (sort (hash-keys known-simple-digests) symbol<?))

;; ----------------------------------------

(define (complex-digest-spec? x)
  (match x
    [(list 'hmac (? basic-digest-spec?)) #t]
    [(list 'cmac (? block-cipher-name?)) #t]
    [(list 'gmac (? block-cipher-name? bcname))
     (let ([bci (block-cipher-name->info bcname)])
       (and bci (= ($bci-block-size bci) 16)))]
    [_ #f]))

(define (complex-digest-spec->info spec [err? #f])
  (match spec
    [(list 'hmac (? basic-digest-spec? dspec))
     (define di (simple-digest-spec->info dspec))
     (define any-sizes '#s(varsize 1 +inf.0 1))
     (define dsize ($di-size di))
     (define bsize ($di-block-size di))
     (dinfo spec dsize bsize #:k dsize #:ks any-sizes)]
    [(list 'cmac (? block-cipher-name? bcname))
     (define bci (block-cipher-name->info bcname))
     (define bsize ($bci-block-size bci))
     (define key-sizes ($bci-key-sizes bci))
     (define key-size (size-set-default key-sizes DEFAULT-KEY-SIZE))
     (dinfo spec bsize bsize #:k key-size #:ks key-sizes)]
    [(list 'gmac (? block-cipher-name? bcname))
     (define bci (block-cipher-name->info bcname))
     (cond [(= ($bci-block-size bci) 16)
            (define key-sizes ($bci-key-sizes bci))
            (define key-size (size-set-default key-sizes DEFAULT-KEY-SIZE))
            (dinfo spec 16 16 #:k key-size #:ks key-sizes)]
           [else #f])]
    [_ (if err? (crypto-error "bad digest spec: ~e" spec) #f)]))

(define (list-complex-digest-specs)
  (define (spec<? a b)
    (or (symbol<? (car a) (car b))
        (and (eq? (car a) (car b)) (symbol<? (cadr a) (cadr b)))))
  (define specs
    (append
     ;; exclude UMAC -- only one impl (nettle)
     (for/list ([dspec (in-list (list-basic-digest-specs))])
       `(hmac ,dspec))
     (for/list ([(bcname bci) (in-hash known-block-ciphers)])
       `(cmac ,bcname))
     (for/list ([(bcname bci) (in-hash known-block-ciphers)]
                #:when (= ($bci-block-size bci) 16))
       `(gmac ,bcname))))
  (sort specs spec<?))

;; ============================================================
;; Cipher Info
;; describes cipher, like AES-GCM or Salsa20

;; block-mode? : Any -> Boolean
(define (block-mode? x)
  (and (memq x known-block-modes) #t))

(define-interface cipher-info$
  #:super (info$)
  #:predicate cipher-info?
  (;; get-spec        ;; -> cipher-spec?
   [ci-cipher-name    (-> cipher-info? symbol?)]
   [ci-mode           (-> cipher-info? (or/c block-mode? 'stream))]
   [ci-type           (-> cipher-info? (or/c 'block 'stream))]
   [ci-aead?          (-> cipher-info? boolean?)]
   [ci-block-size     (-> cipher-info? nat?)] ;; 1 for stream cipher
   [ci-chunk-size     (-> cipher-info? nat?)] ;; natural processing unit (eg, underlying block size)
   [ci-key-size       (-> cipher-info? nat?)]
   [ci-key-sizes      (-> cipher-info? size-set/c)]
   [ci-key-size-ok?   (-> cipher-info? nat? boolean?)]
   [ci-iv-size        (-> cipher-info? nat?)]
   [ci-iv-size-ok?    (-> cipher-info? nat? boolean?)]
   [ci-auth-size      (-> cipher-info? nat?)]
   [ci-auth-size-ok?  (-> cipher-info? nat? boolean?)]
   [ci-uses-padding?  (-> cipher-info? boolean?)])
  #:fallbacks
  (let ()
    (define (ci-key-size-ok? self keysize)
      (size-set-contains? ($ci-key-sizes self) keysize))
    (hasheq 'ci-key-size-ok? ci-key-size-ok?))
  #:generics-prefix $)

(define DEFAULT-KEY-SIZE 16) ;; 128 bits

;; ------------------------------------------------------------
;; Block Ciphers

(struct info:cipher:block
  (spec bci mode)
  #:properties
  (method-properties
   #:export ([cipher-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:cipher:block)
   ;; ----
   (define (%get-spec self) (.spec self))
   ;; ----
   (define (%ci-cipher-name self)
     #;($bci-name (.bci self))
     (car (.spec self)))
   (define (%ci-mode self) (.mode self))
   (define (%ci-type self)
     (case (.mode self)
       [(ecb cbc) 'block]
       [(ofb cfb ctr gcm ocb eax) 'stream]))
   (define (%ci-aead? self)
     (positive? ($ci-auth-size self)))
   (define (%ci-block-size self)
     (case ($ci-type self)
       [(stream) 1] [else ($bci-block-size (.bci self))]))
   (define (%ci-chunk-size self)
     ($bci-block-size (.bci self)))
   (define (%ci-key-size self)
     (size-set-default ($ci-key-sizes self) DEFAULT-KEY-SIZE))
   (define (%ci-key-sizes self)
     ($bci-key-sizes (.bci self)))
   (define (%ci-iv-size self)
     (case (.mode self)
       [(ecb)             0]
       [(cbc ofb cfb ctr) ($ci-chunk-size self)]
       [(gcm ocb eax)     12]
       [else (internal-error "unknown block mode: ~e" (.mode self))]))
   (define (%ci-iv-size-ok? self size)
     (case (.mode self)
       [(ecb)         (= size 0)]
       [(cbc ofb cfb) (= size ($ci-chunk-size self))]
       [(ctr)         (= size ($ci-chunk-size self))]
       [(gcm)         (<= 1 size 16)] ;; actual upper bound much higher
       [(ocb)         (<= 0 size 15)] ;; "no more than 120 bits"
       [(eax)         (<= 0 size 16)] ;; actually unrestricted
       [else #f]))
   (define (%ci-auth-size self)
     (case (.mode self) [(gcm ocb eax) 16] [else 0]))
   (define (%ci-auth-size-ok? self size)
     (case (.mode self)
       [(gcm) (or (<= 12 size 16) (= size 8) (= size 4))]
       [(ocb eax) (<= 1 size 16)]
       [else (= size 0)]))
   (define (%ci-uses-padding? self)
     (eq? ($ci-type self) 'block))
   ;; ----
   (define (%to-write-string self)
     (format "info:cipher:~s" (.spec self))))
  #:property prop:auto-equal+hash (list (struct-field-index spec)))

;; ----------------------------------------
;; BlockMode

;; Block modes are complicated; some modes are defined only for
;; 128-bit block ciphers; others have variable-length IVs/nonces or
;; authentication tags.

(define known-block-modes '(ecb cbc ofb cfb ctr gcm ocb eax))

;; block-mode-block-size-ok? : Symbol Nat -> Boolean
;; Is the block mode compatible with ciphers of the given block size?
(define (block-mode-block-size-ok? mode block-size)
  (case mode
    ;; EAX claims to be block-size agnostic, but nettle restricts to 128-bit block ciphers
    [(gcm ocb eax) (= block-size 16)]
    [else #t]))

;; ----------------------------------------
;; BlockCipherInfo
;; describes block permutation algorithm, like AES

(define-interface block-cipher-info$
  #:predicate block-cipher-info?
  ([bci-name          (-> block-cipher-info? symbol?)]
   [bci-block-size    (-> block-cipher-info? nat?)]
   [bci-key-sizes     (-> block-cipher-info? size-set/c)]
   [bci-key-size-ok?  (-> block-cipher-info? nat? boolean?)]
   [bci-mode-ok?      (-> block-cipher-info? block-mode? boolean?)])
  #:fallbacks
  (let ()
    (define (bci-key-size-ok? self keysize)
      (size-set-contains? ($bci-key-sizes self) keysize))
    (hasheq 'bci-key-size-ok? bci-key-size-ok?))
  #:generics-prefix $)

(struct info:block-cipher
  (name block-size key-sizes)
  #:properties
  (method-properties
   #:export ([block-cipher-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:block-cipher)
   ;; ----
   (define (%bci-name self) (.name self))
   (define (%bci-block-size self) (.block-size self))
   (define (%bci-key-sizes self) (.key-sizes self))
   (define (%bci-mode-ok? self mode)
     (block-mode-block-size-ok? mode (.block-size self)))
   ;; ----
   (define (%to-write-string self)
     (format "info:block-cipher:~s" (.name self))))
  #:property prop:auto-equal+hash (list (struct-field-index name)))

(define known-block-ciphers
  (let ()
    (define (info name block-size key-sizes)
      (info:block-cipher name block-size key-sizes))
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
      (values (info:block-cipher-name bci) bci))))

;; block-cipher-name? : Any -> Boolean
(define (block-cipher-name? x)
  (and (hash-ref known-block-ciphers x #f) #t))

;; block-cipher-name->info : Symbol -> (U BlockCipherInfo #f)
(define (block-cipher-name->info name)
  (hash-ref known-block-ciphers name #f))

;; ------------------------------------------------------------
;; Stream Ciphers

(struct info:cipher:stream (spec chunk-size ivlen key-sizes auth-len)
  #:properties
  (method-properties
   #:export ([cipher-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:cipher:stream)
   ;; ----
   (define (%get-spec self) (.spec self))
   ;; ----
   (define (%ci-cipher-name self) (car (.spec self)))
   (define (%ci-mode self) 'stream)
   (define (%ci-type self) 'stream)
   (define (%ci-aead? self) (positive? ($ci-auth-size self)))
   (define (%ci-block-size self) 1)
   (define (%ci-chunk-size self) (.chunk-size self))
   (define (%ci-key-size self)
     (size-set-default (.key-sizes self) DEFAULT-KEY-SIZE))
   (define (%ci-key-sizes self) (.key-sizes self))
   (define (%ci-iv-size self) (.ivlen self))
   (define (%ci-iv-size-ok? self size) (= size (.ivlen self)))
   (define (%ci-auth-size self) (.auth-len self))
   (define (%ci-auth-size-ok? self size) (= size (.auth-len self)))
   (define (%ci-uses-padding? self) #f)
   ;; ----
   (define (%to-write-string self)
     (format "info:cipher:~s" (.spec self))))
  #:property prop:auto-equal+hash (list (struct-field-index spec)))

(define known-stream-ciphers
  (let ()
    (define (info name chunk-size ivlen key-sizes auth-len)
      (let ([spec (list name 'stream)])
        (info:cipher:stream spec chunk-size ivlen key-sizes auth-len)))
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
      (values ($ci-cipher-name sci) sci))))

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

(define (cipher-spec->info spec)
  (match spec
    [(list (? symbol? cipher) 'stream)
     (stream-cipher-name->info cipher)]
    [(list (? symbol? cipher) (? block-mode? mode))
     (define bci (block-cipher-name->info cipher))
     (and bci ($bci-mode-ok? bci mode)
          (let ([spec (list ($bci-name bci) mode)])
            (info:cipher:block spec bci mode)))]
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

(define-interface pk-info$
  #:super (info$)
  #:predicate pk-info?
  (;; get-spec          ;; -> pk-spec?
   [pk-can-sign?        (-> pk-info? any/c (or/c digest-spec? #f) boolean?)]
   [pk-can-encrypt?     (-> pk-info? any/c boolean?)]
   [pk-can-key-agree?   (-> pk-info? boolean?)]
   [pk-has-params?      (-> pk-info? boolean?)])
  ;; for can-{sign,encrypt}?: pad=#f means "at all?"
  #:generics-prefix $)

(struct info:pk (spec)
  #:properties
  (method-properties
   #:export ([pk-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:pk)
   ;; ----
   (define (%get-spec self) (.spec self))
   ;; ----
   (define (%pk-can-sign? self pad dspec)
     (case (.spec self)
       [(rsa)      ;; impl must check digest
        (and (memq pad '(pkcs1-v1.5 pss pss* #f)) #t)]
       [(dsa ec)   ;; digest ignored for backwards compatibility
        (and (memq pad '(#f)) #t)]
       [(eddsa)    ;; digest must be 'none (future might use digest to mean EdDSAph)
        (and (memq pad '(#f)) (memq dspec '(#f none)) #t)]
       [else #f]))
   (define (%pk-can-encrypt? self pad)
     (case (.spec self)
       [(rsa) (and (memq pad '(pkcs1-v1.5 oaep #f)) #t)]
       [else #f]))
   (define (%pk-can-key-agree? self)
     (and (memq (.spec self) '(dh ec ecx)) #t))
   (define (%pk-has-params? self)
     (and (memq (.spec self) '(dsa dh ec eddsa ecx)) #t))
   ;; ----
   (define (%to-write-string self)
     (format "info:pk:~s" (.spec self))))
  #:property prop:auto-equal+hash (list (struct-field-index spec)))

(define (list-known-pks)
  '(rsa dsa dh ec eddsa ecx))

(define known-pk
  (for/hasheq ([pk (in-list (list-known-pks))])
    (values pk (info:pk pk))))

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

(define-interface kdf-info$
  #:super (info$)
  #:predicate kdf-info?
  (;; get-spec        ;; -> kdf-spec?
   [kdf-salt-mode     (-> kdf-info? (or/c 'req 'opt #f))]
   [kdf-salt-default  (-> kdf-info? (or/c bytes? #f))]) ;; only if mode='opt
  #:generics-prefix $)

(struct info:kdf
  (spec salt-mode salt-default)
  #:properties
  (method-properties
   #:export ([kdf-info$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info:kdf)
   ;; ----
   (define (%get-spec self) (.spec self))
   ;; ----
   (define (%kdf-salt-mode self) (.salt-mode self))
   (define (%kdf-salt-default self) (.salt-default self))
   ;; ----
   (define (%to-write-string self)
     (format "info:kdf:~s" (.spec self))))
  #:property prop:auto-equal+hash (list (struct-field-index spec)))

(define (list-known-simple-kdfs)
  '(argon2d argon2i argon2id scrypt))

(define (kdf-spec? x)
  (match x
    [(? symbol?)
     (and (memq x (list-known-simple-kdfs)) #t)]
    [(list 'pbkdf2 'hmac di)
     (basic-digest-spec? di)]
    [(list 'hkdf di)
     (basic-digest-spec? di)]
    [(list 'concat di)
     (basic-digest-spec? di)]
    [(list 'concat 'hmac di)
     (basic-digest-spec? di)]
    [(list 'ans-x9.63 di)
     (basic-digest-spec? di)]
    [(list 'sp800-108-counter 'hmac di)
     (basic-digest-spec? di)]
    [(list 'sp800-108-feedback 'hmac di)
     (basic-digest-spec? di)]
    [(list 'sp800-108-double-pipeline 'hmac di)
     (basic-digest-spec? di)]
    [_ #f]))

(define (kdf-spec->info spec)
  (define (make-info salt-mode [salt-default #f])
    (info:kdf spec salt-mode salt-default))
  (match spec
    [(? symbol?)
     (and (memq spec (list-known-simple-kdfs)) (make-info 'req))]
    [`(pbkdf2 hmac ,(? basic-digest-spec? dspec))
     (make-info 'req)]
    [`(hkdf ,(? basic-digest-spec? dspec))
     ;; HKDF RFC says if salt absent, set to zeros of length hash *output*
     (define salt (make-bytes (digest-spec-size dspec) 0))
     (make-info 'opt (bytes->immutable-bytes salt))]
    [`(concat ,(? basic-digest-spec? dspec))
     (make-info #f)]
    [`(concat hmac ,(? basic-digest-spec? dspec))
     ;; SP800-56Cr2 says if salt absent, set to zeros of length hash *block*
     (define salt (make-bytes (digest-spec-block-size dspec) 0))
     (make-info 'opt (bytes->immutable-bytes salt))]
    [`(ans-x9.63 ,(? basic-digest-spec? dspec))
     (make-info #f)]
    [`(sp800-108-counter hmac ,(? basic-digest-spec? dspec))
     (make-info #f)]
    [`(sp800-108-feedback hmac ,(? basic-digest-spec? dspec))
     (make-info 'req)]
    [`(sp800-108-double-pipeline hmac ,(? basic-digest-spec? dspec))
     (make-info #f)]
    [_ #f]))

;; list-known-kdfs : -> (Listof KDFSpec)
(define (list-known-kdfs)
  (append (list-known-simple-kdfs)
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(pbkdf2 hmac ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(hkdf ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(concat ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(concat hmac ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(concat hmac ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(ans-x9.63 ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(sp800-108-counter hmac ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(sp800-108-feedback hmac ,di))
          (for/list ([di (in-list (list-basic-digest-specs))])
            `(sp800-108-double-pipeline hmac ,di))
          ))
