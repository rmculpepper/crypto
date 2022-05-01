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
         (only-in racket/base [exact-nonnegative-integer? nat?])
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
;; Predicates

(define (crypto-factory? x) (is-a? x factory<%>))
(define (digest-impl? x) (is-a? x digest-impl<%>))
(define (digest-ctx? x) (is-a? x digest-ctx<%>))
(define (cipher-impl? x) (is-a? x cipher-impl<%>))
(define (cipher-ctx? x) (is-a? x cipher-ctx<%>))
(define (pk-impl? x) (is-a? x pk-impl<%>))
(define (pk-parameters? x) (is-a? x pk-params<%>))
(define (pk-key? x) (is-a? x pk-key<%>))
(define (kdf-impl? x) (is-a? x kdf-impl<%>))

(define (impl? v) (is-a? v impl<%>))
(define (ctx? v) (is-a? v ctx<%>))

(define (pk-read-key? v) (is-a? v pk-read-key<%>))

(define info/c any/c)
(define spec/c any/c)

;; ============================================================
;; General Implementation & Contexts

(define impl<%>
  (interface ()
    [about       (->m string?)]
    [get-info    (->m info/c)]
    [get-spec    (->m spec/c)]
    [get-factory (->m crypto-factory?)]
    ))

(define ctx<%>
  (interface ()
    [about      (->m string?)]
    [get-impl   (->m impl?)]
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

;; bytes-range is alias for slice, except constructor and predicate check for bytes
(begin
  (require (for-syntax racket/base racket/struct-info scramble/struct-info)
           (only-in scramble/slice
                    slice
                    [struct:slice struct:bytes-range]
                    [bytes-slice? bytes-range?]
                    [slice-value bytes-range-bs]
                    [slice-start bytes-range-start]
                    [slice-end bytes-range-end]))
  (define (make-bytes-range bs start end)
    (unless (bytes? bs) (raise-argument-error 'bytes-range "bytes?" 0 bs start end))
    (slice bs start end))
  (define-syntax bytes-range
    (adjust-struct-info
     (list #'struct:bytes-range
           #'make-bytes-range
           #'bytes-range?
           (list #'bytes-range-end #'bytes-range-start #'bytes-range-bs)
           (list #f #f #f)
           #t))))
#;
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
    [get-version    (->m (or/c (listof nat?)))]
    [info           (->m symbol? any)]
    [print-info     (->m void?)]
    [get-name       (->m symbol?)]
    [get-digest     (->m digest-spec? (or/c #f digest-impl?))]
    [get-cipher     (->m cipher-spec? (or/c #f cipher-impl?))]
    [get-pk         (->m pk-spec? (or/c #f pk-impl?))]
    [get-kdf        (->m kdf-spec? (or/c #f kdf-impl?))]
    [get-pk-reader  (->m (or/c #f pk-read-key?))]
    ))

;; ============================================================
;; Digests

(define digest-impl<%>
  (interface (impl<%> digest-info<%>)
    [new-ctx        (->m (or/c #f bytes?) digest-ctx?)]
    [new-hmac-ctx   (->m bytes? digest-ctx?)]
    [digest         (->m input/c (or/c #f bytes?) bytes?)]
    [hmac           (->m bytes? input/c bytes?)]
    ))

(define digest-ctx<%>
  (interface (ctx<%>)
    [digest     (->m input/c bytes?)]
    [update     (->m input/c void?)]
    [final      (->m bytes?)]
    [copy       (->m (or/c #f digest-ctx?))]
    ))

;; ============================================================
;; Ciphers

;; PadMode = (U #f #t)
;;  - #f means no padding
;;  - #t means PKCS7 for block ciphers, none for stream
(define cipher-pad/c boolean?)

(define cipher-impl<%>
  (interface (impl<%> cipher-info<%>)
    [new-ctx
     (->m bytes? (or/c #f bytes?) boolean? cipher-pad/c (or/c #f nat?) boolean?
          cipher-ctx?)]
    ))

(define cipher-ctx<%>
  (interface (ctx<%>)
    ;; Sends {ciper,plain}text to given output port.
    ;; AEAD: auth tag length is set at ctx construction;
    ;; decrypt final takes auth tag (encrypt takes #f)
    [get-encrypt?   (->m boolean?)]
    [update-aad     (->m input/c any)]
    [update         (->m input/c any)]
    [final          (->m (or/c #f bytes?) any)]
    [get-auth-tag   (->m (or/c #f bytes?))]
    ))

;; ============================================================
;; Public-Key Cryptography

(define pk-config/c (listof (list/c symbol? any/c)))
(define pk-sign-pad/c (or/c #f 'pkcs1-v1.5 'pss 'pss*))
(define pk-enc-pad/c (or/c #f 'pkcs1-v1.5 'oaep))

(define pk-impl<%>
  (interface (impl<%>)
    [generate-key    (->m pk-config/c pk-key?)]
    [generate-params (->m pk-config/c pk-parameters?)]
    [can-encrypt?    (->m pk-enc-pad/c boolean?)]
    [can-key-agree?  (->m boolean?)]
    [can-sign        (->m pk-sign-pad/c (or/c #f 'depends 'nodigest 'ignoredg))]
    [can-sign2?      (->m pk-sign-pad/c (or/c #f digest-spec?) boolean?)]
    [has-params?     (->m boolean?)]
    ))

(define pk-read-key<%>
  (interface (impl<%>)
    [read-key        (->m any/c symbol? any/c #|(or/c #f pk-key?)|#)] ;; FIXME
    [read-params     (->m any/c symbol? any/c #|(or/c #f pk-parameters?)|#)] ;; FIXME
    ))

(define pk-params<%>
  (interface (ctx<%>)
    [generate-key       (->m pk-config/c pk-key?)]
    [write-params       (->m symbol? any/c)]
    [get-security-bits  (->m (or/c #f nat?))]
    ))

(define pk-key<%>
  (interface (ctx<%>)
    [is-private?        (->m boolean?)]
    [get-public-key     (->m pk-key?)]
    [get-params         (->m (or/c #f pk-parameters?))]
    [get-security-bits  (->m (or/c #f nat?))]

    [write-key          (->m symbol? any/c)]
    [equal-to-key?      (->m pk-key? boolean?)]

    [sign               (->m bytes? (or/c #f digest-spec?) pk-sign-pad/c bytes?)]
    [verify             (->m bytes? (or/c #f digest-spec?) pk-sign-pad/c bytes? boolean?)]
    ;; In verify, if sig is not well-formed then just return #f, no error.

    [encrypt            (->m bytes? pk-enc-pad/c bytes?)]
    [decrypt            (->m bytes? pk-enc-pad/c bytes?)]

    [compute-secret     (->m (or/c bytes? pk-key?) bytes?)]
    ))

;; ============================================================
;; KDFs

(define kdf-params/c (listof (list/c symbol? any/c)))

(define kdf-impl<%>
  (interface (impl<%>)
    [kdf0       (->m kdf-params/c bytes? (or/c #f bytes?) bytes?)]
    ))
