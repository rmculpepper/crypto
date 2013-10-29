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
(require racket/class)
(provide impl<%>
         ctx<%>
         factory<%>
         digest-impl<%>
         digest-ctx<%>
         hmac-impl<%>
         cipher-impl<%>
         cipher-ctx<%>
         pkey-impl<%>
         pkey-ctx<%>

         factory?
         digest-spec?
         digest-impl?
         digest-ctx?
         cipher-spec?
         cipher-impl?
         cipher-ctx?)

;; ============================================================
;; General Notes

;; All sizes are expressed as a number of bytes unless otherwise noted.
;; eg, (send a-sha1-impl get-size) => 20

;; Whenever a string S is accepted as an input, it is interpreted as
;; equivalent to (string->bytes/utf-8 S).

;; ============================================================
;; General Implementation & Contexts

(define impl<%>
  (interface ()
    ))

(define ctx<%>
  (interface ()
    get-impl    ;; -> impl<%>
    ))

;; ============================================================
;; Implementation Factories

;; FIXME: add all-digests, all-ciphers, all-pkeys methods ???
;; (mostly for testing?)

;; FIXME: add more flexible description language for requests
;; eg PBKDF2-HMAC-SHA1 is specialized by libcrypto, else generic

(define factory<%>
  (interface ()
    #|
    all-digests        ;; -> (listof digest-impl<%>)
    all-ciphers        ;; -> (listof cipher-impl<%>)
    all-pkeys          ;; -> (listof pkey-impl<%>)
    |#
    get-digest-by-name ;; DigestSpec -> digest-impl<%>/#f
    get-cipher-by-name ;; CipherSpec -> cipher-impl<%>/#f
    get-pkey-by-name   ;; symbol -> pkey-impl<%>/#f
    ))

(define (factory? x) (is-a? x factory<%>))

;; A DigestSpec is a symbol in domain of known-digests.
;; A CipherSpec is a symbol in domain of known-cipher-names.

(define known-digests
  ;; References:
  ;;  - http://en.wikipedia.org/wiki/Cryptographic_hash_function
  ;; An entry is of form (list name-symbol hash-size-bits block-size-bits)
  '#hasheq(;; symbol  -> (Hash Block)   -- sizes in bits
           [gost           256  256]
           [md2            128  128]
           [md4            128  512]
           [md5            128  512]
           [ripemd         128  512]
           [ripemd128      128  512]
           [ripemd256      256  512]
           [ripemd160      160  512]
           [ripemd320      320  512]
           [tiger2-128     128  512]
           [tiger2-160     160  512]
           [tiger2-192     192  512]
           ;; Note: 3 versions: Whirlpool-0 (2000), Whirlpool-T (2001), Whirlpool (2003)
           [whirlpool      512  512] 
           [sha0           160  512]
           [sha1           160  512]
           [sha224         224  512]
           [sha256         256  512]
           [sha384         384  1024]
           [sha512         512  1024]

           ;; Many recent hash algorithms can be configured to produce a wide
           ;; range of output sizes, and some have additional parameters.
           ;; List common configurations here, and add another kind of DigestSpec
           ;; to handle the other cases.

           ;; Note: As of 10/2013, SHA3 is not standardized, and SHA3 is expected
           ;; to be different (maybe?) from Keccak as submitted to the NIST contest.
           ;; [sha3-224       224  1152]
           ;; [sha3-256       256  1088]
           ;; [sha3-384       384  832]
           ;; [sha3-512       512  576]
           ;; skein*
           ;; blake*, blake2-*
           ))

(define (digest-spec? x)
  (and (hash-ref known-digests x #f) #t))

(define known-block-ciphers
  ;; References: http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html
  ;; AllowedKeys is one of
  ;;  - (list size ...)
  ;;  - #('variable min max step default)
  '#hasheq(;; symbol  -> (Block AllowedKeys)   -- sizes in bits
           [aes           128   (128 192 256)]
           [des           64    (56)]      ;; key expressed as 64-bits w/ parity bits
           [des-ede2      64    (112)]     ;; key expressed as 128 bits w/ parity bits
           [des-ede3      64    (168)]     ;; key expressed as 192 bits w/ parity bits
           [blowfish      64    #(variable 32 448 8 128)]
           [cast128       64    #(variable 40 128 8 128)]
           [camellia      128   (128 192 256)]
           [idea          64    (128)]
           [rc5           64    #(variable 0 2040 8 128)]
           [rc5-64        128   #(variable 0 2040 8 128)]
           [rc6-64        256   #(variable 0 2040 8 128)]
           [cast256       128   #(variable 128 256 32 128)]
           ;; AES finalists
           [serpent       128   #(variable 0 256 8 128)]
           [twofish       128   #(variable 8 256 8 128)]
           [rc6           128   #(variable 0 2040 8 128)]
           [mars          128   #(variable 128 448 32 128)] ;; aka Mars-2 ???
           ))

;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;; TODO
;;  - change cipher-impl to leave key-size unfixed; only need
;;    when creating ctx or calling encrypt/decrypt
;;  - key-size-ok? : CipherName Nat -> Boolean
;;  - check-key-size : CipherName Nat -> void or error

(define known-stream-ciphers
  '#hasheq(;; symbol  ->  IV  AllowedKeys      -- sizes in bits
           [rc4           0   #(variable 40 2048 8 128)]
           [salsa20       64  (256)]
           [salsa20/8     64  (256)]
           [salsa20/12    64  (256)]
           ))

(define known-ciphers-abbrev
  '#hasheq(;; symbol -> CipherSpec
           [aes-128-cbc (cbc aes 128)]
           [aes-192-cbc (cbc aes 192)]
           [aes-256-cbc (cbc aes 256)]
           [aes-128-ctr (ctr aes 128)]
           [aes-192-ctr (ctr aes 192)]
           [aes-256-ctr (ctr aes 256)]))

;; Mode effects:
;;   ecb: iv=none,    block same
;;   cbc: iv=1 block, block same
;;   ofb: iv=1 block, stream cipher
;;   cfb: iv=1 block, stream cipher
;;   ctr: iv=1 block, stream cipher
;;   gcm: iv=???, ???                                -- FIXME
(define known-block-modes '(ecb cbc ofb cfb ctr gcm))

;; A CipherSpec is one of
;;  - a symbol in known-ciphers-abbrev
;;  - (list* 'stream CipherName)
;;  - (list* BlockMode CipherName KeySpec)
;; BlockMode is one of 'ecb, 'cbc, 'cfb, 'ofb, 'ctr.
;; CipherName is a symbol in the domain od known-block-ciphers.
;; KeySpec is one of
;;  - '()
;;  - (list Nat)

(define (cipher-spec? x)
  (cond [(symbol? x)
         (and (hash-ref known-ciphers-abbrev #f) #t)]
        [(and (pair? x) (eq? (car x) 'stream))
         (match (cdr x)
           [(list cipher-name)
            (and (hash-ref known-stream-ciphers cipher-name #f) #t)]
           [_ #f])]
        [(and (pair? x) (memq (car x) known-block-modes))
         (match (cdr x)
           [(list cipher-name)
            (and (hash-ref known-block-ciphers cipher-name #f) #t)]
           [(list cipher-name key-size)
            (let ([entry (hash-ref known-block-ciphers cipher-name #f)])
              (and entry
                   (key-size-matches? key-size (cadr entry))))]
           [_ #f])]
        [else #f]))

(define (key-size-matches? size allowed-sizes)
  (if (list? 


;; ============================================================
;; Digests

;; FIXME: elim end indexes: simplifies interface, clients can check easily
;; FIXME: add hmac-buffer! method

(define digest-impl<%>
  (interface (impl<%>)
    get-name      ;; -> any -- eg, 'md5, 'sha1, 'sha256
    get-size      ;; -> nat
    get-block-size;; -> nat
    get-hmac-impl ;; who -> digest-impl<%>
    new-ctx       ;; -> digest-ctx<%>
    generate-hmac-key ;; -> bytes

    can-digest-buffer!? ;; -> boolean
    digest-buffer!      ;; sym bytes nat nat bytes nat -> nat

    can-hmac-buffer!?   ;; -> boolean
    hmac-buffer!        ;; sym bytes bytes nat nat bytes nat -> nat
    ))

;; FIXME: add some option to reset instead of close; add to new-ctx or final! (???)
(define digest-ctx<%>
  (interface (ctx<%>)
    update   ;; sym bytes nat nat -> void
    final!   ;; sym bytes nat nat -> nat
    copy     ;; sym -> digest-ctx<%>/#f
    ))

(define hmac-impl<%>
  (interface (impl<%>)
    get-digest ;; -> digest-impl<%>
    new-ctx    ;; sym bytes -> digest-ctx<%>
    ))

(define (digest-impl? x) (is-a? x digest-impl<%>))
(define (digest-ctx? x) (is-a? x digest-ctx<%>))

;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 (in practice, same as PKCS5)
;; Maybe support more padding modes in future?

(define cipher-impl<%>
  (interface (impl<%>)
    get-name       ;; -> any -- eg, "AES-128", "DES-EDE" (???)
    get-key-size   ;; -> nat
    get-block-size ;; -> nat
    get-iv-size    ;; -> nat/#f

    new-ctx         ;; sym bytes bytes/#f boolean PadMode -> cipher-ctx<%>
                    ;; who key   iv       enc?    pad
    generate-key    ;; -> bytes
    generate-iv     ;; -> bytes/#f
    ))

;; Some disadvantages to current cipher update! and final! methods:
;;  - client has to know how much output to expect (output buffer free space)
;;  - not all impls produce output at same rate
;;    - eg openssl command-line tool doesn't produce output until final! (???)
;;    - eg gcrypt accepts only multiples of blocks (???)

(define cipher-ctx<%>
  (interface (ctx<%>)
    update!  ;; sym bytes nat nat bytes nat nat -> nat
    final!   ;; sym bytes nat nat -> nat
    ))

(define (cipher-impl? x) (is-a? x cipher-impl<%>))
(define (cipher-ctx? x) (is-a? x cipher-ctx?))

;; ============================================================
;; Public-Key Cryptography

(define pkey-impl<%>
  (interface (impl<%>)
    read-key     ;; sym boolean bytes nat nat -> pkey-ctx<%>
    generate-key ;; (listof ???) -> pkey-ctx<%>
    digest-ok?   ;; digest-impl<%> -> boolean
    can-encrypt? ;; -> boolean
    ))

(define pkey-ctx<%>
  (interface (ctx<%>)
    is-private?             ;; -> boolean
    get-max-signature-size  ;; -> nat
    get-key-size/bits       ;; -> nat

    write-key       ;; sym boolean -> bytes
    equal-to-key?   ;; pkey-ctx<%> -> boolean

    sign!           ;; sym digest-ctx<%> bytes nat nat -> nat
    verify          ;; sym digest-ctx<%> bytes nat nat -> boolean

    encrypt/decrypt ;; sym boolean boolean bytes nat nat -> bytes
    ))
