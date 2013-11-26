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
(require racket/class
         "catalog.rkt")
(provide impl<%>
         ctx<%>
         factory<%>
         digest-impl<%>
         digest-ctx<%>
         hmac-impl<%>
         cipher-impl<%>
         cipher-ctx<%>
         pk-impl<%>
         pk-read-key<%>
         pk-params<%>
         pk-key<%>
         random-impl<%>

         crypto-factory?
         digest-impl?
         digest-ctx?
         cipher-impl?
         cipher-ctx?
         pk-impl?
         pk-parameters?
         pk-key?
         random-impl?)

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
    get-spec    ;; -> *Spec
    get-factory ;; -> factory<%>
    ))

(define ctx<%>
  (interface ()
    get-impl    ;; -> impl<%>
    ))

;; ============================================================
;; Implementation Factories

;; FIXME: add all-digests, all-ciphers, all-pks methods ???
;; (mostly for testing?)

;; FIXME: add more flexible description language for requests
;; eg PBKDF2-HMAC-SHA1 is specialized by libcrypto, else generic

(define factory<%>
  (interface ()
    #|
    all-digests        ;; -> (listof digest-impl<%>)
    all-ciphers        ;; -> (listof cipher-impl<%>)
    all-pks          ;; -> (listof pk-impl<%>)
    |#
    get-digest  ;; DigestSpec -> digest-impl<%>/#f
    get-cipher  ;; CipherSpec -> cipher-impl<%>/#f
    get-pk      ;; PKSpec -> pk-impl<%>/#f
    get-random  ;; -> random-impl<%>/#f
    get-pk-reader ;; -> pk-read-key<%>/#f
    ))

(define (crypto-factory? x) (is-a? x factory<%>))


;; ============================================================
;; Digests

;; FIXME: elim end indexes: simplifies interface, clients can check easily
;; FIXME: add hmac-buffer! method

(define digest-impl<%>
  (interface (impl<%>)
    ;; get-spec      ;; -> DigestSpec
    get-size      ;; -> nat
    get-block-size;; -> nat
    get-hmac-impl ;; -> digest-impl<%>
    new-ctx       ;; -> digest-ctx<%>

    can-digest-buffer!? ;; -> boolean
    digest-buffer!      ;; bytes nat nat bytes nat -> nat

    can-hmac-buffer!?   ;; -> boolean
    hmac-buffer!        ;; bytes bytes nat nat bytes nat -> nat
    ))

;; FIXME: add some option to reset instead of close; add to new-ctx or final! (???)
(define digest-ctx<%>
  (interface (ctx<%>)
    update   ;; bytes nat nat -> void
    final!   ;; bytes nat nat -> nat
    copy     ;; -> digest-ctx<%>/#f
    ))

(define hmac-impl<%>
  (interface (impl<%>)
    get-digest ;; -> digest-impl<%>
    new-ctx    ;; bytes -> digest-ctx<%>
    ))

(define (digest-impl? x) (is-a? x digest-impl<%>))
(define (digest-ctx? x) (is-a? x digest-ctx<%>))

;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 for block ciphers, none for stream
;; Maybe support more padding modes in future?

(define cipher-impl<%>
  (interface (impl<%>)
    ;; get-spec       ;; -> CipherSpec
    get-block-size ;; -> nat
    get-iv-size    ;; -> nat

    new-ctx         ;; bytes bytes/#f boolean PadMode -> cipher-ctx<%>
                    ;; key   iv       enc?    pad
    ))

;; Some disadvantages to current cipher update! and final! methods:
;;  - client has to know how much output to expect (output buffer free space)
;;  - not all impls produce output at same rate
;;    - eg openssl command-line tool doesn't produce output until final! (???)
;;    - eg gcrypt accepts only multiples of blocks (???)

(define cipher-ctx<%>
  (interface (ctx<%>)
    update!  ;; bytes nat nat bytes nat nat -> nat
    final!   ;; bytes nat nat -> nat
    ))

(define (cipher-impl? x) (is-a? x cipher-impl<%>))
(define (cipher-ctx? x) (is-a? x cipher-ctx<%>))

;; ============================================================
;; Public-Key Cryptography

(define pk-impl<%>
  (interface (impl<%>)
    generate-key    ;; GenKeySpec -> pk-key<%>
    generate-params ;; GenParamSpec -> pk-params<%>
    can-key-agree?  ;; -> boolean
    can-sign?       ;; -> boolean
    can-encrypt?    ;; -> boolean
    has-params?     ;; -> boolean
    ))

(define pk-read-key<%>
  (interface (impl<%>)
    read-key        ;; SerializedKey -> pk-key<%>/#f
    read-params     ;; SerializedParams -> pk-params<%>/#f
    ))

(define pk-params<%>
  (interface (ctx<%>)
    generate-key    ;; GenKeySpec -> pk-key<%>
    write-params    ;; ParamsFormat -> SerializedParams
    ))

(define pk-key<%>
  (interface (ctx<%>)
    is-private?             ;; -> boolean
    get-public-key          ;; -> pk-key<%>
    get-params              ;; -> pk-params<%> or #f

    write-key       ;; KeyFormat -> SerializedKey
    equal-to-key?   ;; pk-key<%> -> boolean

    sign            ;; bytes DigestSpec Padding -> bytes
    verify          ;; bytes DigestSpec Padding bytes -> boolean

    encrypt         ;; bytes Padding -> bytes
    decrypt         ;; bytes Padding -> bytes

    compute-secret  ;; bytes -> bytes
    ))

;; KeyFormat
;;  any symbol which is the head of a legal SerializedKey or SerializedParams
;;  #f means *impl-specific*, may alias another defined format

;; SerializedKey is one of
;;  - (list 'libcrypto (U 'rsa 'dsa 'ec 'dh) (U 'public 'private) bytes)
;;  - ...

;; SerializedParams is one of
;;  - (list 'libcrypto (U 'dsa 'ec 'dh) bytes)
;;  - ...

;; Padding is a symbol (eg 'oaep) or #f
;;  #f means *impl-specific* default

;; GenKeySpec is a (listof (list symbol any)) w/o duplicates,
;; where only known keys are allowed (impl-specific).

(define (pk-impl? x) (is-a? x pk-impl<%>))
(define (pk-parameters? x) (is-a? x pk-params<%>))
(define (pk-key? x) (is-a? x pk-key<%>))

;; ============================================================
;; Randomness

(define random-impl<%>
  (interface (impl<%>)
    ;; get-spec          ;; -> 'random
    random-bytes!        ;; bytes nat nat RandomLevel -> void

    ok?                  ;; -> boolean
    can-add-entropy?     ;; -> boolean
    add-entropy          ;; bytes real -> void
    ))

;; RandomLevel is one of 'strong, 'very-strong.

(define (random-impl? x) (is-a? x random-impl<%>))
