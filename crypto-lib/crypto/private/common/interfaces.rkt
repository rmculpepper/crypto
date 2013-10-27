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
         pkey-ctx<%>)

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
    get-digest-by-name ;; symbol -> digest-impl<%>/#f
    get-cipher-by-name ;; symbol -> cipher-impl<%>/#f
    get-pkey-by-name   ;; symbol -> pkey-impl<%>/#f
    ))

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
    generate-key+iv ;; -> (values bytes bytes/#f)
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
