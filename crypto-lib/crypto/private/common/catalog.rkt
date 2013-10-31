;; Copyright 2013 Ryan Culpepper
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
         racket/match)
(provide (all-defined-out))

;; ============================================================
;; Digests

(define known-digests
  ;; References:
  ;;  - http://en.wikipedia.org/wiki/Cryptographic_hash_function
  ;; An entry is of form (list name-symbol hash-size block-size)
  '#hasheq(;; symbol  ->   [Hash  Block]   -- sizes in bytes
           [gost        .  [ 32   32 ]]
           [md2         .  [ 16   16 ]]
           [md4         .  [ 16   64 ]]
           [md5         .  [ 16   64 ]]
           [ripemd      .  [ 16   64 ]]
           [ripemd128   .  [ 16   64 ]]
           [ripemd256   .  [ 32   64 ]]
           [ripemd160   .  [ 20   64 ]]
           [ripemd320   .  [ 40   64 ]]
           [tiger2-128  .  [ 16   64 ]]
           [tiger2-160  .  [ 20   64 ]]
           [tiger2-192  .  [ 24   64 ]]
           ;; Note: 3 versions: Whirlpool-0 (2000), Whirlpool-T (2001), Whirlpool (2003)
           [whirlpool   .  [ 64   64 ]] 
           [sha0        .  [ 20   64 ]]
           [sha1        .  [ 20   64 ]]
           [sha224      .  [ 28   64 ]]
           [sha256      .  [ 32   64 ]]
           [sha384      .  [ 48   128]]
           [sha512      .  [ 64   128]]

           ;; Many recent hash algorithms can be configured to produce a wide
           ;; range of output sizes, and some have additional parameters.
           ;; List common configurations here, and add another kind of DigestSpec
           ;; to handle the other cases.

           ;; Note: As of 10/2013, SHA3 is not standardized, and SHA3 is expected
           ;; to be different (maybe?) from Keccak as submitted to the NIST contest.
           ;; [sha3-224       28   144]
           ;; [sha3-256       32   136]
           ;; [sha3-384       48   104]
           ;; [sha3-512       64   72 ]
           ;; skein*
           ;; blake*, blake2-*
           ))

;; A DigestSpec is a symbol in domain of known-digests.

(define (digest-spec? x)
  (and (hash-ref known-digests x #f) #t))

(define (digest-spec-size spec)
  (match (hash-ref known-digests spec #f)
    [(list size block-size) size]
    [_ #f]))

(define (digest-spec-block-size spec)
  (match (hash-ref known-digests spec #f)
    [(list size block-size) block-size]
    [_ #f]))


;; ============================================================
;; Ciphers

;; AllowedKeys is one of
;;  - (list key-size-nat ...+)
;;  - #s(variable-size min-nat max-nat step-nat)
(define-struct variable-size (min max step) #:prefab)

(define known-block-ciphers
  ;; References: http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html
  ;; AllowedKeys is one of
  ;;  - (list size ...+)
  ;;  - (vector 'variable min max step)
  '#hasheq(;; symbol  -> (Block AllowedKeys)   -- sizes in bytes
           [aes        .  [ 16    (16 24 32)]]
           [des        .  [ 8     (7)]]      ;; key expressed as 8 bytes w/ parity bits
           [des-ede2   .  [ 8     (14)]]     ;; key expressed as 16 bytes w/ parity bits
           [des-ede3   .  [ 8     (21)]]     ;; key expressed as 24 bytes w/ parity bits
           [blowfish   .  [ 8     #s(variable-size 32 56 1)]]
           [cast128    .  [ 8     #s(variable-size 40 16 1)]]
           [camellia   .  [ 16    (16 24 32)]]
           [idea       .  [ 8     (16)]]
           [rc5        .  [ 8     #s(variable-size 0 255 1)]]
           [rc5-64     .  [ 16    #s(variable-size 0 255 1)]]
           [rc6-64     .  [ 32    #s(variable-size 0 255 1)]]
           [cast256    .  [ 16    #s(variable-size 16 32 4)]]
           ;; AES finalists
           [serpent    .  [ 16    #s(variable-size 0 32 1)]]
           [twofish    .  [ 16    #s(variable-size 8 32 1)]]
           [rc6        .  [ 16    #s(variable-size 0 255 1)]]
           [mars       .  [ 16    #s(variable-size 16 56 4)]] ;; aka Mars-2 ???
           ))

(define known-stream-ciphers
  '#hasheq(;; symbol  ->  IV  AllowedKeys      -- sizes in bytes
           [rc4        .  [ 0   #s(variable-size 5 256 1)]]
           [salsa20    .  [ 8   (32)]]
           [salsa20/8  .  [ 8   (32)]]
           [salsa20/12 .  [ 8   (32)]]
           ))

;; Mode effects:
;;   ecb: iv=none,    block same, 0 added
;;   cbc: iv=1 block, block same, 0 added
;;   ofb: iv=1 block, stream cipher, 0 added
;;   cfb: iv=1 block, stream cipher, 0 added
;;   ctr: iv=1 block, stream cipher, 0 added
;;   gcm: iv=???, ???                                -- FIXME
;;   ccm: NOTE: offline/nonincremental: needs length before starting; don't support
(define known-block-modes
  '(;; Mode IVblocks IVbytes Type Added
    [ecb 0 0 block 0]
    [cbc 1 0 block 0]
    [ofb 1 0 stream 0]
    [cfb 1 0 stream 0]
    [ctr 1 0 stream 0]
    ;;[gcm ? ? stream ?]
    ))

(define (block-mode? x) (and (symbol? x) (assq x known-block-modes) #t))

;; A CipherSpec is one of
;;  - (list StreamCipherName 'stream)
;;  - (list BlockCipherName BlockMode)
;; BlockMode is one of 'ecb, 'cbc, 'cfb, 'ofb, 'ctr.
;; BlockCipherName is a symbol in the domain of known-block-ciphers,
;; StreamCipherName is a symbol in the domain of known-stream-ciphers.

(define (cipher-spec? x)
  (match x
    [(list (? symbol? cipher-name) 'stream)
     (and (hash-ref known-stream-ciphers cipher-name #f) #t)]
    [(list (? symbol? cipher-name) (? block-mode?))
     (and (hash-ref known-block-ciphers cipher-name #f) #f)]
    [_ #f]))

;; ----------------------------------------

(define (cipher-spec-key-sizes cipher-spec)
  (match cipher-spec
    [(list cipher-name 'stream)
     (match (hash-ref known-stream-ciphers cipher-name #f)
       [(list _ allowed-keys) allowed-keys]
       [_ #f])]
    [(list cipher-name (? block-mode? mode))
     (match (hash-ref known-block-ciphers cipher-name #f)
       [(list _ allowed-keys) allowed-keys]
       [_ #f])]))

(define MIN-DEFAULT-KEY-SIZE 128)

(define (cipher-spec-default-key-size cipher-spec)
  (define allowed (cipher-spec-key-sizes cipher-spec))
  (cond [(list? allowed)
         (or (for/or ([size (in-list allowed)] #:when (>= size MIN-DEFAULT-KEY-SIZE)) size)
             (max allowed))]
        [(variable-size? allowed)
         (let* ([minks (variable-size-min allowed)]
                [maxks (variable-size-max allowed)]
                [step (variable-size-step allowed)]
                [diff (- MIN-DEFAULT-KEY-SIZE minks)]
                [diff-steps (quotient diff step)]
                [best-default (+ MIN-DEFAULT-KEY-SIZE
                                 (* step diff-steps)
                                 (if (zero? (remainder diff step)) step 0))])
           (cond [(<= minks best-default maxks)
                  best-default]
                 [else maxks]))]
        [else #f]))

(define (cipher-spec-block-size cipher-spec)
  (match cipher-spec
    [(list cipher-name 'stream) 1]
    [(list (? symbol? cipher-name) (? block-mode? mode))
     (let ([entry (hash-ref known-block-ciphers cipher-name #f)])
       (match entry
         [(list block-size allowed-keys)
          (match (assq mode known-block-modes)
            [(list _ _ _ 'stream _) 1]
            [(list _ _ _ 'block _) block-size])]
         [_ #f]))]))

(define (cipher-spec-iv-size cipher-spec)
  (match cipher-spec
    [(list cipher-name 'stream)
     (match (hash-ref known-stream-ciphers cipher-name #f)
       [(list iv-bytes allowed-keys)
        iv-bytes])]
    [(list (? symbol? cipher-name) (? block-mode? mode))
     (match (hash-ref known-block-ciphers cipher-name #f)
       [(list block-size allowed-keys)
        (match (assq mode known-block-modes)
          [(list _ iv-blocks iv-bytes _ _)
           (+ iv-bytes (* iv-blocks block-size))])]
       [_ #f])]))

;; bad-key-size : CipherSpec Nat -> (U #f '() AllowedKeys)
;; #f means ok; '() means unknown cipher; AllowedKeys means given size not allowed
(define (bad-key-size cipher-spec key-size)
  (let ([allowed (cipher-spec-key-sizes cipher-spec)])
    (cond [(list? allowed)
           (if (member key-size allowed) #f allowed)]
          [(variable-size? allowed)
           (if (and (<= (variable-size-min allowed) key-size (variable-size-max allowed))
                    (zero? (quotient (- key-size (variable-size-min allowed))
                                     (variable-size-step allowed))))
               #f
               allowed)]
          [else '()])))

;; key-size-ok? : CipherSpec Nat -> Boolean
(define (key-size-ok? cipher-spec key-size)
  (not (bad-key-size cipher-spec key-size)))

;; check-key-size : symbol CipherSpec Nat -> void or error
(define (check-key-size who cipher-spec key-size)
  (let ([allowed (bad-key-size cipher-spec key-size)])
    (cond [(eq? allowed #f) (void)]
          [(eq? allowed '())
           (error who "unknown cipher\n  cipher: ~e" cipher-spec)]
          [(list? allowed)
           (error who
                  "bad key size for cipher\n  cipher: ~e\n  given: ~e\n  allowed key sizes: ~a"
                  cipher-spec
                  key-size
                  (string-join (map number->string allowed) ", "))]
          [(variable-size? allowed)
           (error who
                  "bad key size for cipher\n  cipher: ~e\n  given: ~e\n  allowed key sizes: ~a"
                  cipher-spec
                  key-size
                  (format "from ~a to ~a in multiples of ~a"
                          (variable-size-min allowed)
                          (variable-size-max allowed)
                          (variable-size-step allowed)))])))
