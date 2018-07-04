;; Copyright 2018 Ryan Culpepper
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
(provide b64-encode
         b64-encode/utf-8
         b64-decode
         b64-decode/utf-8
         ab64-encode
         ab64-encode/utf-8
         ab64-decode
         ab64-decode/utf-8)

;; Base64 is an encoding of binary data into a subset of printable ASCII strings.
;; No padding, no linebreaking.

;; References:
;; - https://en.wikipedia.org/wiki/Base64

;; ----------------------------------------

(define b64-prefix #"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
(define std-endcodes #"+/")
(define alt-endcodes #"./")
(define url-endcodes #"-_")

;; encode1 : Bytes[2] Nat[0..63] -> Byte
(define (encode1 endcodes k)
  (cond [(< k 62) (bytes-ref b64-prefix k)]
        [(< k 64) (bytes-ref endcodes (- k 62))]))

;; decode1 : Bytes[2] Byte -> Nat[0..63]
(define (decode1 endcodes n #:who [who 'decode1])
  (cond [(<= (char->integer #\A) n (char->integer #\Z))
         (+ 0 (- n (char->integer #\A)))]
        [(<= (char->integer #\a) n (char->integer #\z))
         (+ 26 (- n (char->integer #\a)))]
        [(<= (char->integer #\0) n (char->integer #\9))
         (+ 52 (- n (char->integer #\0)))]
        [(= n (bytes-ref endcodes 0)) 62]
        [(= n (bytes-ref endcodes 1)) 63]
        [else (error who "bad base64(~a) code: ~e" endcodes n)]))

;; ----------------------------------------

;; encode : Bytes Bytes[2] -> Bytes
(define (encode src endcodes #:who who)
  (define (code k) (encode1 endcodes k))
  (define srclen (bytes-length src))
  (define outlen
    (+ (* 4 (quotient srclen 3))
       (case (remainder srclen 3) [(0) 0] [(1) 2] [(2) 3])))
  (define out (make-bytes outlen))
  (for ([srci (in-range 0 srclen 3)]
        [outi (in-range 0 outlen 4)])
    (define n (read-triplet src srci srclen))
    (write-quad out outi outlen n code))
  out)

(define (read-triplet src srci srclen)
  (define (get srci) (if (< srci srclen) (bytes-ref src srci) 0))
  (+ (arithmetic-shift (get (+ srci 0)) 16)
     (arithmetic-shift (get (+ srci 1)) 8)
     (get (+ srci 2))))

(define (write-quad out outi outlen n code)
  (define (put outi v) (when (< outi outlen) (bytes-set! out outi v)))
  (put (+ outi 0) (code (bitwise-bit-field n 18 24)))
  (put (+ outi 1) (code (bitwise-bit-field n 12 18)))
  (put (+ outi 2) (code (bitwise-bit-field n 6  12)))
  (put (+ outi 3) (code (bitwise-bit-field n 0  6))))

;; ----------------------------------------

;; decode : Bytes Bytes[2] -> Bytes
(define (decode src endcodes #:who who)
  (define (dc k) (decode1 endcodes k #:who who))
  (define srclen (bytes-length src))
  (define srclen%4 (remainder srclen 4))
  (define outlen
    (+ (* 3 (quotient srclen 4))
       (case srclen%4 [(0) 0] [(2) 1] [(3) 2])))
  (define out (make-bytes outlen))
  ;; Decode main part (full quartets)
  (for ([srci (in-range 0 srclen 4)]
        [outi (in-range 0 outlen 3)])
    (define n (read-quad src srci srclen dc))
    (write-triplet out outi outlen n))
  out)

(define (read-quad src srci srclen dc)
  (define (get srci) (if (< srci srclen) (dc (bytes-ref src srci)) 0))
  (+ (arithmetic-shift (get (+ srci 0)) 18)
     (arithmetic-shift (get (+ srci 1)) 12)
     (arithmetic-shift (get (+ srci 2))  6)
     (get (+ srci 3))))

(define (write-triplet out outi outlen n)
  (define (put outi v) (when (< outi outlen) (bytes-set! out outi v)))
  (put (+ outi 0) (bitwise-bit-field n 16 24))
  (put (+ outi 1) (bitwise-bit-field n 8  16))
  (put (+ outi 2) (bitwise-bit-field n 0  8)))

;; ----------------------------------------

;; coerce-src : Symbol (U Bytes String) -> Bytes
(define (coerce-src who src)
  (cond [(bytes? src) src]
        [(string? src) (string->bytes/utf-8 src)]
        [else (raise-argument-error who "(or/c string? bytes?)" src)]))

;; ============================================================

(define (b64-encode src [endcodes std-endcodes] #:who [who 'b64-encode])
  (encode (coerce-src who src) endcodes #:who who))
(define (b64-encode/utf-8 src [endcodes std-endcodes] #:who [who 'b64-encode/utf-8])
  (bytes->string/utf-8 (b64-encode src endcodes #:who who)))
(define (b64-decode src [endcodes std-endcodes] #:who [who 'b64-decode])
  (decode (coerce-src who src) endcodes #:who who))
(define (b64-decode/utf-8 src [endcodes std-endcodes] #:who [who 'b64-decode/utf-8])
  (bytes->string/utf-8 (b64-decode src endcodes #:who who)))

(define (ab64-encode src #:who [who 'ab64-encode])
  (b64-encode src alt-endcodes #:who who))
(define (ab64-encode/utf-8 src #:who [who 'ab64-encode/utf-8])
  (b64-encode/utf-8 src alt-endcodes #:who who))
(define (ab64-decode src #:who [who 'ab64-decode])
  (b64-decode src alt-endcodes #:who who))
(define (ab64-decode/utf-8 src #:who [who 'ab64-decode/utf-8])
  (b64-decode/utf-8 src alt-endcodes #:who who))
