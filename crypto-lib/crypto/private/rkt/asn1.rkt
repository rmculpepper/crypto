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
         base256->signed

         wrap-bit-string
         bit-string->der
         decode-bit-string

         ia5string?
         wrap-ia5string
         ia5string->der
         decode-ia5string

         wrap-integer
         integer->der
         decode-integer

         wrap-null
         null->der

         wrap-object-identifier
         object-identifier->der
         decode-object-identifier
         OID

         wrap-octet-string
         octet-string->der

         printable-string?
         wrap-printable-string
         printable-string->der
         decode-printable-string

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
  (unless (exact-nonnegative-integer? n)
    (raise-argument-error 'unsigned->base256 "exact-nonnegative-integer?" n))
  (nonnegative-integer->base256 n #f))

(define (signed->base256 n)
  (unless (exact-integer? n)
    (raise-argument-error 'signed->base256 "exact-integer?" n))
  (if (negative? n)
      (negative-integer->base256 n)
      (nonnegative-integer->base256 n #t)))

(define (nonnegative-integer->base256 n as-signed?)
  (if (zero? n)
      #"0"
      (apply bytes
             (let loop ([n n] [acc null])
               (if (zero? n)
                   (if (and as-signed? (> (car acc) 127))
                       (cons 0 acc)
                       acc)
                   (let-values ([(q r) (quotient/remainder n 8)])
                     (loop q (cons r acc))))))))

(define (negative-integer->base256 n)
  (apply bytes
         (let loop ([n n] [acc null])
           (cond [(<= -128 n -1)
                  (cons (+ 256 n) acc)]
                 [else
                  (let* ([b (bitwise-bit-field n 0 8)]
                         [q (arithmetic-shift n -8)])
                    (loop q (cons b acc)))]))))

(define (ubyte->sbyte u)
  (if (< u 128) u (- u 256)))
(define (sbyte->ubyte s)
  (if (>= s 0) s (+ s 256)))

(define (base256->unsigned bs)
  (for/fold ([n 0]) ([b (in-bytes bs)])
    (+ (arithmetic-shift n 8) b)))

(define (base256->signed bs)
  (if (and (positive? (bytes-length bs)) (> (bytes-ref bs 0) 127))
      (- (base256->unsigned bs)
         (arithmetic-shift 1 (* 8 (bytes-length bs))))
      (base256->unsigned bs)))

;; ============================================================

;; Conventions:

;; wrap-<type> : bytes -> bytes
;; Accepts contents as given, appends tag and length

;; <type>->der : ??? -> bytes

;; === Bit string ===

;; wrap-bit-string : bytes -> bytes
(define (wrap-bit-string c)
  (wrap 'BIT-STRING 'primitive c))

;; bit-string->der : bytes nat -> bytes
;; Given bytes and number of trailing bits not significant (0-7)
(define (bit-string->der bits [trailing-unused 0])
  (wrap-bit-string
   (bytes-append (bytes trailing-unused)
                 bits)))

;; decode-bit-string : bytes -> bytes
;; Given encoded content, returns raw bit string
;; NOTE: trailing-unused bits must be zero!
(define (decode-bit-string c)
  (when (zero? (bytes-length c))
    (error 'decode-bit-string "ill-formed bit-string encoding: empty"))
  (let ([trailing-unused (bytes-ref c 0)])
    (unless (zero? trailing-unused)
      (error 'decode-bit-string "partial-octet bit strings not supported"))
    (subbytes c 1 (bytes-length c))))

;; === Choice ===

;; Not needed yet.

;; === IA5String (ie, ASCII string) ===

;; ia5string? : any -> boolean
(define (ia5string? s)
  (and (string? s)
       (for/and ([c (in-string s)])
         (< (char->integer c) 256))))

;; wrap-ia5string : bytes -> bytes
(define (wrap-ia5string c)
  (wrap 'IA5String 'primitive c))

;; ia5string->der : ia5string -> bytes
(define (ia5string->der s)
  (unless (ia5string? s)
    (raise-argument-error 'ia5string->der "ia5string?" s))
  (wrap-ia5string (string->bytes/latin-1 s)))

;; decode-ia5string : bytes -> string
(define (decode-ia5string bs)
  (define s (bytes->string/latin-1 bs))
  (unless (ia5string? s)
    (error 'decode-ia5string "not an ia5string: ~e" s))
  s)

;; === Integer ===

;; base-256, two's-complement (!!), most significant octet first
;; zero encoded as 1 octet

;; wrap-integer : bytes -> bytes
(define (wrap-integer c)
  (wrap 'INTEGER 'primitive c))

;; integer->der : exact-integer -> bytes
(define (integer->der n)
  (wrap-integer (signed->base256 n)))

;; decode-integer : bytes -> integer
;; Given encoded integer, returns raw integer
(define (decode-integer bs)
  (base256->signed bs))

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
              (map encode-oid-component cs*))))))

(define (encode-oid-component c)
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

(define (decode-object-identifier bs)
  (when (zero? (bytes-length bs))
    (error 'decode-object-identifier "empty" bs))
  (define in (open-input-bytes bs))
  (define b1 (read-byte in))
  (list* (quotient b1 40) (remainder b1 40)
         (let loop ()
           (if (eof-object? (peek-byte in))
               null
               (let ([c (decode-oid-component in)])
                 (cons c (loop)))))))

(define (decode-oid-component in)
  (let loop ([c 0])
    (let ([next (read-byte in)])
      (cond [(eof-object? next)
             (error 'decode-object-identifier "incomplete component")]
            [(< next 128)
             (+ next (arithmetic-shift c 7))]
            [else
             (loop (+ (- next 128) (arithmetic-shift c 7)))]))))

;; === Octet String ===

;; wrap-octet-string : bytes -> bytes
(define (wrap-octet-string c)
  (wrap 'OCTET-STRING 'primitive c))

;; octet-string->der : bytes -> bytes
(define (octet-string->der bs)
  (wrap-octet-string bs))

;; === Printable string ===

(define (printable-string? s)
  (and (string? s) (regexp-match? #rx"^[-a-zA-Z0-9 '()+,./:=?]*$" s)))

;; wrap-printable-string : bytes -> bytes
(define (wrap-printable-string c)
  (wrap 'PrintableString 'primitive c))

;; printable-string : printable-string -> bytes
(define (printable-string->der s)
  (unless (printable-string? s)
    (raise-argument-error 'printable-string->der "printable-string?"))
  (wrap-printable-string (string->bytes/latin-1 s)))

;; decode-printable-string : bytes -> printable-string
(define (decode-printable-string bs)
  (let ([s (bytes->string/latin-1 bs)])
    (if (printable-string? s)
        s
        (error 'decode-printable-string "not a printable string: ~e" s))))

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

;; Asn1-Type is one of
;; - any
;; - Base-Type
;; - (sequence Asn1-Element-Type ...)
;; - (sequence-of Asn1-Type ...)
;; - (set Asn1-Element-Type ...)
;; - (set-of Asn1-Type ...)
;; - (choice Asn1-Element-Type ...)
;; - (named symbol Asn1-Type)
;; - (lazy (PromiseOf Asn1-Type))

;; Asn1-Element-Type is one of
;; - (element MaybeName MaybeTag Asn1-Type MaybeOptionalDefault)

;; MaybeName is one of
;; - Symbol
;; - #f

;; MaybeTag is one of
;; - (explicit-tag class tag)
;; - (implicit-tag class tag)
;; - #f

;; MaybeOptionalDefault is one of
;; - (optional)
;; - (default Value)
;; - #f

;; ----

;; ASN1 decoder is one of
;; - 'decode -- decode known types
;; - 'stop   -- leave encoded (asn1-encoded struct)
;; - something like an ASN1-Type with other decoders at leaves???

;; ----

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
    (case (car tag)
      [(OBJECT-IDENTIFIER)
       (list 'OBJECT-IDENTIFIER (decode-object-identifier c))]
      [(NULL)
       '(NULL)]
      [else
       (case (caddr tag)
         [(primitive)
          (list (car tag) c)]
         [(constructed)
          (cons (car tag) (read-ders (open-input-bytes c)))])])))

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
