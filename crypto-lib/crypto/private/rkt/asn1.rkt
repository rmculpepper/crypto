;; Copyright 2014 Ryan Culpepper
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
(provide unsigned->base256
         signed->base256
         base256->unsigned

         wrap-integer
         integer->der
         wrap-null
         null->der
         wrap-object-identifier
         object-identifier->der
         OID
         wrap-octet-string
         octet-string->der
         wrap-sequence
         sequence->der
         wrap-set
         set->der

         unwrap-der
         read-der)

;; Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html

(define type-tag-classes
  '(universal application private context-specific))

(define type-tags
  '([INTEGER            2   primitive]
    [BIT-STRING         3   primitive]
    [OCTET-STRING       4   primitive]
    [NULL               5   primitive]
    [OBJECT-IDENTIFIER  6   primitive]
    [SEQUENCE          16   constructed]
    [SET               17   constructed]
    [PrintableString   19   primitive]
    [T61String         20   primitive]
    [IA5String         22   primitive]
    [UTCTime           23   primitive]))

;; ----

;; BER (restricted to definite-length) encoding has 3:
;; - identifier - class, tag, primitive vs constructed
;; - length - number of contents octets
;; - content

;; == Primitive, definite-length ==
;; Tags:
;;   for low tag number (0-30):
;;     bits 8,7 are class, bit 6 is 0, bits 5-1 are tag number
;;     classes: universal (0,0); application (0,1); context-sensitive (1,0); private (1,1)
;;   for high tag number: ... (don't need yet)
;; Length octets:
;;   short (0 to 127): bit 8 is 0, bits 7-1 are value
;;   long (128 to 2^1008-1):
;;     first octet: bit 8 is 1, bits 7-1 give number of following length octets
;;     rest of octets are base-256 number

;; == Constructed, definite-length ==
;; Tags: same as primitive, except bit 6 is 1 to indicate constructed
;; Length octets: same as primitive

;; == Alternative tagging ==
;; class is context-sensitive unless overridden in defn
;; Implicit:
;;   change tag of component
;;   inherit prim/cons from underlying type
;; Explicit:
;;   adds outer tag
;;   always constructed

;; ----------------------------------------

;; wrap : symbol (U 'primitive 'constructd) bytes -> bytes
(define (wrap type p/c c)
  (bytes-append (get-tag type p/c) (length-code c) c))

;; get-tag : symbol (U 'primitive 'constructed) -> bytes
(define (get-tag type p/c)
  (bytes
   (+ (cond [(assq type type-tags)
             => cadr]
            [else (error 'get-tag "unknown type: ~e" type)])
      (case p/c
        [(primitive) 0]
        [(constructed) (expt 2 (sub1 6))]
        [else (error 'get-tag "expected (or/c 'primitive 'constructed), got: ~e" p/c)]))))

;; length-code : (U nat bytes) -> bytes
(define (length-code n)
  (if (bytes? n)
      (length-code (bytes-length n))
      (cond [(<= 0 n 127)
             (bytes n)]
            [else
             (let ([nc (unsigned->base256 n)])
               (unless (< 128 (bytes-length nc))
                 (error 'length-code "length too long: ~e" n))
               (bytes-append
                (bytes (bitwise-ior 128 (bytes-length nc)))
                nc))])))

(define (unsigned->base256 n)
  (integer->base256 n #f))

(define (signed->base256 n)
  (if (negative? n)
      (error 'signed->base256 "not yet implemented")
      (integer->base256 n #t)))

(define (integer->base256 n as-signed?)
  (if (zero? n)
      #"0"
      (apply bytes
             (let loop ([n n] [acc null])
               (if (zero? n)
                   acc
                   (let-values ([(q r) (quotient/remainder n 8)])
                     (loop q (cons r acc))))))))

(define (ubyte->sbyte u)
  (if (< u 128) u (- u 256)))
(define (sbyte->ubyte s)
  (if (>= s 0) s (+ s 256)))

(define (base256->unsigned lbs)
  (for/fold ([n 0]) ([b (in-bytes lbs)])
    (+ (arithmetic-shift n 8) b)))

;; ============================================================

;; Conventions:

;; wrap-<type> : bytes -> bytes
;; Accepts contents as given, appends tag and length

;; <type>->der : ??? -> bytes

;; === Bit string ===

;; Not needed yet.

;; === Choice ===

;; Not needed yet.

;; === IA5String ===

;; IA5 = ASCII
;; Not needed yet.

;; === Integer ===

;; base-256, two's-complement (!!), most significant octet first
;; zero encoded as 1 octet

;; wrap-integer : bytes -> bytes
(define (wrap-integer c)
  (wrap 'INTEGER 'primitive c))

;; integer->der : exact-integer -> bytes
(define (integer->der n)
  (wrap-integer (signed->base256 n)))

;; === Null ===

;; wrap-null : bytes -> bytes
(define (wrap-null c)
  (wrap 'NULL 'primitive c))

(define (null->der)
  (wrap-null #""))

;; === Object Identifier ==

;; If OID = c1, c2, ... cN, then
;; first octet is 40*c1 + c2
;; following octets are c3, ... cN encoded as follows:
;;   base-128, most-significant first, high bit set on all but last octet of encoding

;; wrap-object-identifier : bytes -> bytes
(define (wrap-object-identifier c)
  (wrap 'OBJECT-IDENTIFIER 'primitive c))

;; object-identifier->der : (listof (U nat (list symbol nat))) -> bytes
(define (object-identifier->der cs)
  (let ([cs (for/list ([c (in-list cs)])
              (if (list? c) (cadr c) c))])
    (wrap-object-identifier
     (let ([c1 (car cs)]
           [c2 (cadr cs)]
           [cs* (cddr cs)])
       (apply bytes-append
              (bytes (+ (* 40 c1) c2))
              (map encode-component cs*))))))

(define (encode-component c)
  (define (loop c acc)
    (if (zero? c)
        acc
        (let-values ([(q r) (quotient/remainder c 128)])
          (loop q (cons (bitwise-ior 128 r) acc)))))
  (apply bytes
         (let-values ([(q r) (quotient/remainder c 128)])
           (loop q (list r)))))

(define-syntax-rule (OID c ...)
  (object-identifier->der (quote (c ...))))

;; === Octet String ===

;; wrap-octet-string : bytes -> bytes
(define (wrap-octet-string c)
  (wrap 'OCTET-STRING 'primitive c))

;; octet-string->der : bytes -> bytes
(define (octet-string->der bs)
  (wrap-octet-string bs))

;; === Printable string ===

;; Not needed yet.

;; === Sequence ===

;; wrap-sequence : bytes -> bytes
(define (wrap-sequence c)
  (wrap 'SEQUENCE 'constructed c))

;; sequence->der : (listof bytes) -> bytes
;; Argument is a list of DER-encoded values.
;; Assumes DEFAULT and OPTIONAL parts have already been stripped from list.
(define (sequence->der lst)
  (wrap-sequence (apply bytes-append lst)))

;; === Sequence Of ===

;; wrap-sequence-of : bytes -> bytes
(define (wrap-sequence-of c)
  (wrap 'SEQUENCE 'constructed c))

;; sequence-of->der : (listof bytes) -> bytes
;; Argument is a list of DER-encoded values.
(define (sequence-of->der lst)
  (wrap-sequence-of (apply bytes-append lst)))

;; ===  Set ===

;; wrap-set : bytes -> bytes
(define (wrap-set c)
  (wrap 'SET 'constructed c))

;; set->der : (listof bytes) -> bytes
;; Argument is a list of DER-encoded values
(define (set->der lst)
  (wrap-set (apply bytes-append (sort lst bytes<?))))

;; === Set Of ===

;; wrap-set-of : bytes -> bytes
(define (wrap-set-of c)
  (wrap 'SET 'constructed c))

;; set-of->der : (listof bytes) -> bytes
;; Argument is a list of DER-encoded values
(define (set-of->der lst)
  (wrap-set-of (apply bytes-append (sort lst bytes<?))))

;; === T61String ===

;; Not needed yet.

;; === UTCTime ===

;; Not needed yet.


;; ============================================================

;; FIXME: add checking for premature EOF, etc

;; UnwrappedDER is one of
;; - (list symbol bytes)                ;; primitive type
;; - (list 'SEQUENCE UnwrappedDER ...)
;; - (list 'SET UnwrappedDER ...)

;; unwrap-der : bytes -> UnwrappedDER
(define (unwrap-der der)
  (define in (open-input-bytes der))
  (begin0 (read-der in)
    (unless (eof-object? (peek-char in))
      (error 'unwrap-der "bytes left over"))))

;; read-der : input-port -> UnwrappedDER
(define (read-der in)
  (let* ([tag (read-tag in)]
         [len (read-length-code in)]
         [c (read-bytes len in)])
    (case (caddr tag)
      [(primitive)
       (list (car tag) c)]
      [(constructed)
       (cons (car tag) (read-ders (open-input-bytes c)))])))

(define (read-ders in)
  (if (eof-object? (peek-char in))
      null
      (cons (read-der in) (read-ders in))))

(define (read-tag in)
  (let* ([t (read-byte in)]
         [c? (bitwise-bit-set? t (sub1 6))]
         [tn (bitwise-and t 31)])
    (when (or (bitwise-bit-set? t (sub1 8))
              (bitwise-bit-set? t (sub1 7)))
      (error 'unwrap-der "only universal tags implemented"))
    (unless (<= 0 tn 30)
      (error 'unwrap-der "only low tags implemented"))
    (define entry
      (let loop ([alist type-tags])
        (cond [(null? alist)
               (error 'unwrap-der "unknown tag: ~e" tn)]
              [(= (cadr (car alist)) tn)
               (car alist)]
              [else (loop (cdr alist))])))
    (unless (eq? (caddr entry)
                 (if c? 'constructed 'primitive))
      (error 'unwrap-der "primitive/constructed mismatch"))
    entry))

(define (read-length-code in)
  (let ([l (read-byte in)])
    (cond [(<= 0 l 127)
           l]
          [else
           (let* ([ll (- l 128)]
                  [lbs (read-bytes ll in)])
             (base256->unsigned lbs))])))
