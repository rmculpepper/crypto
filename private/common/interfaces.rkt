;; Copyright 2012 Ryan Culpepper
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
         digest-impl<%>
         digest-ctx<%>
         cipher-impl<%>
         cipher-ctx<%>
         pkey-impl<%>
         pkey-ctx<%>)

;; ============================================================
;; General Implementation & Contexts

(define impl<%>
  (interface ()
    new-ctx   ;; sym ??? -> ctx<%>
    get-name  ;; -> string
    ))

(define ctx<%>
  (interface ()
    get-impl    ;; -> impl<%>

    ;; A State is a symbol, usually one of 'need-init, 'ready, 'closed.
    get-state   ;; -> State
    set-state!  ;; State/#f -> void
    check-state! ;; sym (listof State) -> void
    ))

#|
TODO: define factory interfaces or otherwise say how to find impls

All sizes are expressed as a number of bytes unless otherwise noted.
eg, (send a-sha1-impl get-size) => 20
|#

;; ============================================================
;; Digests

(define digest-impl<%>
  (interface (impl<%>)
    ;; get-name   ;; -> string -- eg, "MD5", "SHA-1", "SHA-256"
    get-size      ;; -> nat

    get-hmac-impl ;; who -> digest-impl<%>
    hmac-buffer   ;; sym bytes bytes nat nat -> bytes/#f
                  ;;  -- fast/convenience method, may return #f

    generate-hmac-key  ;; -> bytes
    ))

(define digest-ctx<%>
  (interface (ctx<%>)
    ;; Usage: { update! }* final!
    update!  ;; sym bytes nat nat -> void
    final!   ;; sym bytes nat nat -> nat

    copy     ;; sym -> digest-ctx<%>/#f
    ))

;; ============================================================
;; Ciphers

(define cipher-impl<%>
  (interface (impl<%>)
    ;; get-family  ;; -> string -- eg, "Blowfish", "AES"
    ;; get-name    ;; -> string -- eg, "AES-128", "DES-EDE" (???)
    ;; get-mode    ;; -> symbol -- eg, 'ecb, 'cbc
    get-key-size   ;; -> nat
    get-block-size ;; -> nat
    get-iv-size    ;; -> nat/#f

    generate-key+iv ;; -> (values bytes bytes/#f)
    ))

;; FIXME: Perhaps impl should offer list of key sizes,
;; wait until set-key! in context to decide?

(define cipher-ctx<%>
  (interface (ctx<%>)
    ;; Interface assumes internal buffer for output.
    ;; Usage: interleaved Writing and Reading
    ;;   where Writing =  set-key! set-iv! { update! }* close!
    ;;         Reading = { read! }*
    ;;set-key!  ;; sym bytes nat nat -> void
    ;;set-iv!   ;; sym bytes nat nat -> void
    ;;update!   ;; sym bytes nat nat -> void
    ;;close!    ;; sym -> void
    ;;read!     ;; sym bytes nat nat bool -> nat

    update!  ;; sym bytes nat nat bytes nat nat -> nat
    final!   ;; sym bytes nat nat -> nat
    ))

;; ============================================================
;; Public-Key Cryptography

(define pkey-impl<%>
  (interface (impl<%>)
    read-key ;; sym boolean bytes nat nat -> pkey-ctx<%>
    generate-key ;; (listof ???) -> pkey-ctx<%>

    digest-ok? ;; digest-impl<%> -> boolean
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
