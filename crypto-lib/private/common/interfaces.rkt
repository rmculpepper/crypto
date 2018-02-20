;; Copyright 2012-2018 Ryan Culpepper
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
         racket/contract/base
         "catalog.rkt")
(provide impl<%>
         ctx<%>
         state<%>
         factory<%>
         digest-impl<%>
         digest-ctx<%>
         cipher-impl<%>
         cipher-ctx<%>
         pk-impl<%>
         pk-read-key<%>
         pk-params<%>
         pk-key<%>
         kdf-impl<%>

         input/c
         (struct-out bytes-range)

         crypto-factory?
         digest-impl?
         digest-ctx?
         cipher-impl?
         cipher-ctx?
         pk-impl?
         pk-parameters?
         pk-key?
         kdf-impl?)

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
    about       ;; -> String
    get-info    ;; -> *Info
    get-spec    ;; -> *Spec
    get-factory ;; -> factory<%>
    ))

(define ctx<%>
  (interface ()
    about       ;; -> String
    get-impl    ;; -> impl<%>
    ))

(define state<%>
  (interface ()
    with-state ;; [#:ok States #:pre State #:post State #:msg Any] (-> Any) -> Any
    ;; Acquires mutex, checks state, and updates state before and after calling proc.
    ))

;; ============================================================
;; Inputs

;; An Input is one of
;; - Bytes
;; - String
;; - InputPort
;; - (bytes-range Bytes Nat Nat)
;; - (Listof Input)
(struct bytes-range (bs start end)
  #:guard (lambda (buf start end _name)
            (unless (bytes? buf)
              (raise-argument-error 'bytes-range "bytes?" 0 buf start end))
            (unless (exact-nonnegative-integer? start)
              (raise-argument-error 'bytes-range "exact-nonnegative-integer?" 1 buf start end))
            (unless (exact-nonnegative-integer? end)
              (raise-argument-error 'bytes-range "exact-nonnegative-integer?" 2 buf start end))
            (unless (<= start end (bytes-length buf))
              (raise-range-error 'bytes-range "bytes" "ending " end buf start (bytes-length buf) 0))
            (values buf start end)))

(define input/c
  (flat-rec-contract input/c
    (or/c bytes? string? input-port? bytes-range? (listof input/c))))

;; ============================================================
;; Implementation Factories

(define factory<%>
  (interface ()
    get-version ;; (Listof Nat)/#f
    info        ;; Symbol -> Any
    print-info  ;; -> Void
    get-name    ;; -> Symbol, for testing
    get-digest  ;; DigestSpec -> digest-impl<%>/#f
    get-cipher  ;; CipherSpec -> cipher-impl<%>/#f
    get-pk      ;; PKSpec -> pk-impl<%>/#f
    get-pk-reader ;; -> pk-read-key<%>/#f
    get-kdf     ;; KDFSpec -> kdf-impl<%>/#f
    ))

(define (crypto-factory? x) (is-a? x factory<%>))

;; ============================================================
;; Digests

(define digest-impl<%>
  (interface (impl<%> digest-info<%>)
    new-ctx        ;; -> digest-ctx<%>
    new-hmac-ctx   ;; Bytes -> digest-ctx<%>
    digest         ;; Input -> Bytes
    hmac           ;; Bytes Input -> Bytes
    ))

(define digest-ctx<%>
  (interface (ctx<%>)
    digest     ;; Input -> Bytes
    update     ;; Input -> Void
    final      ;; -> Bytes
    copy       ;; -> digest-ctx<%> or #f
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
  (interface (impl<%> cipher-info<%>)
    new-ctx         ;; Bytes Bytes/#f Bool Pad Nat/#f Bool -> cipher-ctx<%>
                    ;; key   iv       enc? pad taglen attached?
    ))

(define cipher-ctx<%>
  (interface (ctx<%>)
    ;; Sends {ciper,plain}text to given output port.
    ;; AEAD: auth tag length is set at ctx construction;
    ;; decrypt final takes auth tag (encrypt takes #f)
    get-encrypt? ;; -> boolean
    update-aad ;; Input -> Void
    update     ;; Input -> Void
    final      ;; Bytes/#f -> Void
    get-auth-tag ;; -> Bytes/#f
    ))

(define (cipher-impl? x) (is-a? x cipher-impl<%>))
(define (cipher-ctx? x) (is-a? x cipher-ctx<%>))

;; ============================================================
;; Public-Key Cryptography

(define pk-impl<%>
  (interface (impl<%>)
    generate-key    ;; GenKeySpec -> pk-key<%>
    generate-params ;; GenParamSpec -> pk-params<%>
    can-key-agree?  ;; Symbol/#f -> boolean
    can-sign?       ;; Symbol/#f DigestSpec/#f -> boolean
    can-encrypt?    ;; -> boolean
    has-params?     ;; -> boolean
    ))

(define pk-read-key<%>
  (interface (impl<%>)
    read-key        ;; Datum KeyFormat -> pk-key<%>/#f
    read-params     ;; Datum ParamsFormat -> pk-params<%>/#f
    ))

(define pk-params<%>
  (interface (ctx<%>)
    generate-key    ;; GenKeySpec -> pk-key<%>
    write-params    ;; ParamsFormat -> Datum
    ))

(define pk-key<%>
  (interface (ctx<%>)
    is-private?             ;; -> boolean
    get-public-key          ;; -> pk-key<%>
    get-params              ;; -> pk-params<%> or #f

    write-key       ;; KeyFormat -> Datum
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
;; KDFs

;; A KDFSpec is one of
;;  - (list 'pbkdf2 'hmac DigestSpec)
;;  - 'bcrypt
;;  - 'scrypt

(define kdf-impl<%>
  (interface (impl<%>)
    kdf ;; KDFParams bytes bytes -> bytes
    ))

(define (kdf-impl? x) (is-a? x kdf-impl<%>))
