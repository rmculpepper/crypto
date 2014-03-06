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
(require (for-syntax racket/base syntax/parse)
         racket/match
         racket/promise
         "types.rkt")
(provide (all-defined-out))

;; Reference: http://luca.ntop.org/Teaching/Appunti/asn1.html

;; ============================================================

;; Asn1-Type is one of
;; - (type:base symbol)
;; - (type:sequence (list Asn1-Element-Type ...))
;; - (type:sequence-of Asn1-Type)
;; - (type:set (list Asn1-Element-Type ...))
;; - (type:set-of Asn1-Type)
;; - (type:choice (list Asn1-Element-Type ...))
;; - (type:ref symbol Asn1-Type)
(struct asn1-type () #:transparent)
(struct asn1-type:base asn1-type (name) #:transparent)
(struct asn1-type:sequence asn1-type (elts) #:transparent)
(struct asn1-type:sequence-of asn1-type (elt) #:transparent)
(struct asn1-type:set asn1-type (elts) #:transparent)
(struct asn1-type:set-of asn1-type (elt) #:transparent)
(struct asn1-type:choice asn1-type (elts) #:transparent)
(struct asn1-type:defined asn1-type (name promise) #:transparent)

;; Asn1-Element-Type is one of
;; - (element Symbol MaybeTag Asn1-Type MaybeOptionalDefault)
;; Desugars explicit tagging into asn1-type:explicit-tag-sequence.
(struct element-type (name tag type option) #:transparent)
(struct asn1-type:explicit-tag-sequence asn1-type:sequence () #:transparent)

;; MaybeTag is one of
;; - (list class nat)    -- implicit or desugared explicit
;; - #f

;; MaybeOptionalDefault is one of
;; - (list 'optional)
;; - (list 'default Value)
;; - #f

(define-syntax define-asn1-type
  (syntax-parser
   [(define-asn1-type name:id type)
    #:declare type (expr/c #'asn1-type?)
    #'(define name
        (asn1-type:defined 'name (delay type.c)))]))

(begin-for-syntax
 (define-splicing-syntax-class tag-class
   (pattern (~seq #:universal) #:with tclass #'universal)
   (pattern (~seq #:private)   #:with tclass #'private)
   (pattern (~seq #:application) #:with tclass #'application)
   (pattern (~seq) #:with tclass #'context-specific))
 (define-splicing-syntax-class option-clause
   (pattern (~seq #:optional)
            #:with option #''(optional))
   (pattern (~seq #:default v:expr)
            #:with option #'(list 'default v))
   (pattern (~seq)
            #:with option #''#f))

 (define-syntax-class element
   (pattern [name:id #:explicit etag:nat type :option-clause]
            #:declare type (expr/c #'asn1-type?)
            #:with et #'(element-type 'name '(implicit etag)
                                      (asn1-type:explicit-tag-sequence (list type.c))
                                      option))
   (pattern [name:id #:implicit itag:nat type :option-clause]
            #:declare type (expr/c #'asn1-type?)
            #:with et #'(element-type 'name '(implicit itag) type.c option))
   (pattern [name:id type :option-clause]
            #:declare type (expr/c #'asn1-type?)
            #:with et #'(element-type 'name '#f type.c option))))

(define-syntax Sequence
  (syntax-parser
   [(Sequence e:element ...)
    #'(asn1-type:sequence (check-sequence-types (list e.et ...)))]))

(define-syntax SequenceOf
  (syntax-parser
   [(SequenceOf type)
    #:declare type (expr/c #'asn1-type?)
    #'(asn1-type:sequence-of type.c)]))

(define-syntax Set
  (syntax-parser
   [(Set e:element ...)
    #'(asn1-type:set (check-set-types (list e.et ...)))]))

(define-syntax SetOf
  (syntax-parser
   [(SetOf type)
    #:declare type (expr/c #'asn1-type?)
    #'(asn1-type:set-of type.c)]))

(define-syntax Choice
  (syntax-parser
   [(Choice e:element ...)
    #'(asn1-type:choice (check-choice-types (list e.et ...)))]))

(define (check-sequence-types ets)
  ;; All runs of optional components in a SEQUENCE must have distinct
  ;; tags, and their tags must be distinct from following required
  ;; component. (p 220)
  ;; FIXME
  ets)

(define (check-set-types ets)
  ;; All components of a SET must have distinct tags. (p226)
  (check-duplicate-types 'Set ets))

(define (check-choice-types ets)
  ;; All components of a CHOICE must have distinct tags. (p236)
  (check-duplicate-types 'Choice ets))

(define (check-duplicate-types who ets)
  (define tags (apply append (map type->tags ets)))
  (when (memq #f tags)
    ;; Do not allow indeterminate tag in CHOICE or SET
    (error who "indeterminate tag"))
  (cond [(let loop ([tags tags])
           (and (pair? tags)
                (or (member (car tags) (cdr tags))
                    (loop (cdr tags)))))
         (error who "duplicate tag: ~e" (car tags))])
  ets)

;; FIXME: references to defined types may cause force-cycle problems

;; type->tags : (U Asn1-Type Element-Type) -> (listof (U Tag #f))
;; #f means all possible tags; collides with everything
(define (type->tags t)
  (match t
    [(asn1-type:base base-type)
     (cond [(type->tag-entry base-type)
            => (lambda (te)
                 (list (list 'universal (tag-entry-tagn te))))]
           [else
            (error 'type->tags "unknown base type: ~e" base-type)])]
    [(asn1-type:sequence _)
     (list (tag-entry-tag (type->tag-entry 'SEQUENCE)))]
    [(asn1-type:sequence-of _)
     (list (tag-entry-tag (type->tag-entry 'SEQUENCE)))]
    [(asn1-type:set _)
     (list (tag-entry-tag (type->tag-entry 'SET)))]
    [(asn1-type:set-of _)
     (list (tag-entry-tag (type->tag-entry 'SET)))]
    [(asn1-type:choice elts)
     (apply append (map (type->tags elts)))]
    [(asn1-type:defined name promise)
     (type->tags (force promise))]
    [(element-type name tag type option)
     (if tag
         (list tag)
         (type->tags type))]))

;; ============================================================

(define INTEGER (asn1-type:base 'INTEGER))
(define BIT-STRING (asn1-type:base 'BIT-STRING))
(define OCTET-STRING (asn1-type:base 'OCTET-STRING))
(define NULL (asn1-type:base 'NULL))
(define OBJECT-IDENTIFIER (asn1-type:base 'OBJECT-IDENTIFIER))
(define PrintableString (asn1-type:base 'PrintableString))
;; T61String
(define IA5String (asn1-type:base 'IA5String))
;; UTCTime

;; ============================================================

;; ASN1 decoder is one of
;; - 'decode -- decode known types
;; - 'stop   -- leave encoded (asn1-encoded struct)
;; - something like an ASN1-Type with other decoders at leaves???

;; Control decoder by mapping of names (type names and element names?)
;; to decoder-control-function.

;; A DecoderControlFun is one of
;; - 'decode
;; - 'stop
;; - ((U Asn1-Type Asn1-Element-Type) Asn1-Tag Bytes -> Any)

;; TODO:
;; decompose-der : bytes -> (values Asn1-Tag Bytes)

;; ============================================================

;; Encode/Decode hooks

;; DER-encode-hooks : (parameterof (listof (cons Asn1-Type DER-Encode-Hook)))
;; A DER-Encode-Hook is (list 'pre (Asn1-Type Any -> Bytes)), provides value bytes
(define DER-encode-hooks (make-parameter null))

;; DER-decode-hooks : (parameterof (listof (cons Asn1-Type DER-Decode-Hook)))
;; A DER-Decode-Hook is one of
;; - (list 'pre  (Asn1-Type Bytes -> Any))
;; - (list 'post (Asn1-Type Any   -> Any))
;; Note: a pre-hook prevents a post-hook from running.
(define DER-decode-hooks (make-parameter null))

;; search-hooks : Symbol (listof Key) (listof (list Key Symbol Value))
;;             -> (list Key Symbol Value) or #f
;; Search back to front.
(define (search-hooks kind keys hooks)
  (let loop ([keys keys])
    (and (pair? keys)
         (or (loop (cdr keys))
             (get-hook kind (car keys) hooks)))))

;; get-hook : Symbol Key (listof (list Key Symbol Value)) -> (list Key Symbol Value) or #f
(define (get-hook kind key hooks)
  (for/or ([hook (in-list hooks)])
    (and (eq? (car hook) key)
         (eq? (cadr hook) kind)
         hook)))

;; ============================================================

;; Encode : T V[T] -> E[T]
;; - bytes/integer/etc    Base-Type                          -> E[_]
;; - (SequenceOf T)       (list V[T] ...)                    -> E[_]
;; - (Sequence [L T] ...) (list 'sequence (list L V[T]) ...) -> E[_]
;; - (Sequence [L T] ...) (list V[T] ...)                    -> E[_]
;; - (SetOf T)            (list V[T] ...)                    -> E[_]
;; - (Set [L T] ...)      (list 'set (list L V[T]) ...)      -> E[_]
;; - (Choice [L T] ...)   (list L V[T])                      -> E[_]

(define (DER-encode type v [alt-tag #f])
  (let loop ([type type] [alt-types null])
    (match type
      [(asn1-type:base base-type)
       (wrap base-type (DER-encode-value type v alt-types) alt-tag)]
      [(asn1-type:sequence elts)
       (wrap 'SEQUENCE (DER-encode-value type v alt-types) alt-tag)]
      [(asn1-type:sequence-of type*)
       (wrap 'SEQUENCE (DER-encode-value type v alt-types) alt-tag)]
      [(asn1-type:set elts)
       (wrap 'SET (DER-encode-value type v alt-types) alt-tag)]
      [(asn1-type:set-of type*)
       (wrap 'SET (DER-encode-value type v alt-types) alt-tag)]
      [(asn1-type:choice elts)
       (match v
         [(list (? symbol? sym) v*)
          (match-define (element-type _ tag* type* _)
            (for/or ([elt (in-list elts)])
              (and (eq? (element-type-name elt) sym) elt)))
          (DER-encode type* v* tag*)]
         [_ (error 'asn1-encode "bad value for Choice type\n  value: ~e" v)])]
      [(asn1-type:defined name promise)
       (loop (force promise) (cons type alt-types))])))

(define (DER-encode-value type v [alt-types null])
  ;; Search alt-types back-to-front, then type, for hook to apply
  (define hook
    (let ([hooks (DER-encode-hooks)])
      (or (search-hooks 'pre alt-types hooks)
          (get-hook 'pre type hooks))))
  (if hook
      (let ([hook-f (caddr hook)])
        (let ([b (hook-f type v)])
          (unless (bytes? b)
            (error 'DER-encode-value
                   "value returned by encode-hook is not bytes\n  value: ~e"
                   b))
          b))
      (DER-encode-value* type v)))

(define (DER-encode-value* type v)
  (match type
    [(asn1-type:base base-type)
     (DER-encode-base* base-type v)]
    [(asn1-type:sequence elts)
     (encode-sequence-value (filter values (DER-encode-sequence* elts v)))]
    [(asn1-type:sequence-of type*)
     (unless (list? v)
       (error 'DER-encode-value "bad value for SequenceOf type\n  value: ~e" v))
     (encode-sequence-value
      (for/list ([v* (in-list v)])
        (DER-encode type* v* #f)))]
    [(asn1-type:set elts)
     (encode-set-value (filter values (DER-encode-set* elts v)))]
    [(asn1-type:set-of type*)
     (unless (list? v)
       (error 'DER-encode-value "bad value for SetOf type\n  value: ~e" v))
     (encode-set-value
      (for/list ([v* (in-list v)])
        (DER-encode type* v* #f)))]
    [(asn1-type:choice elts)
     (error 'DER-encode-value "internal error: bad type\n  type: ~e" type)]
    [(asn1-type:defined name promise)
     (error 'DER-encode-value "internal error: bad type\n  type: ~e" type)]))

(define (DER-encode-base* base-type v)
  (define (bad-value [expected #f])
    (error 'DER-encode-value
           "bad value for type\n  type: ~s\n  value: ~e~a"
           base-type v
           (if expected (format "\n  expected: ~a" expected) "")))
  (case base-type
    [(INTEGER)
     (unless (exact-integer? v) (bad-value 'exact-integer?))
     (let ([b (signed->base256 v)])
       (eprintf "b = ~s\n" b)
       b)]
    [(BIT-STRING)
     (unless (bytes? v) (bad-value 'bytes?))
     (encode-bit-string v)]
    [(OCTET-STRING)
     (unless (bytes? v) (bad-value 'bytes?))
     v]
    [(NULL)
     (unless (eq? v #f) (bad-value "#f"))
     #""]
    [(OBJECT-IDENTIFIER)
     (unless (and (list? v) (andmap exact-nonnegative-integer? v))
       (bad-value '(listof exact-nonnegative-integer?)))
     (encode-object-identifier v)]
    ;; Sequence[Of], Set[Of]
    [(PrintableString)
     (unless (printable-string? v) (bad-value 'printable-string?))
     (string->bytes/latin-1 v)]
    ;; T61String
    [(IA5String)
     (unless (ia5string? v) (bad-value 'ia5string?))
     (string->bytes/latin-1 v)]
    ;; UTCTime
    [else (error 'DER-encode-value "unsupported base type\n  type: ~s" base-type)]))

;; DER-encode-sequence* : (listof ElementType) Any -> (listof (U Bytes #f))
(define (DER-encode-sequence* elts v)
  (match v
    [(cons 'sequence lvs)
     (match lvs
       [(list (list (? symbol?) _) ...)
        (let loop ([elts elts] [lvs lvs])
          (cond [(and (null? elts) (null? lvs))
                 null]
                [(null? elts)
                 (error 'DER-encode-value
                        "unexpected field in Sequence value\n  value: ~e\n  field: ~s"
                        v (car (car lvs)))]
                [else
                 (match (car elts)
                   [(element-type name tag* type* option)
                    (cond [(and (pair? lvs)
                                (eq? (car (car lvs)) name))
                           (cons (DER-encode type* (cadr (car lvs)) tag*)
                                 (loop (cdr elts) (cdr lvs)))]
                          [option
                           (loop (cdr elts) lvs)]
                          [else
                           (error 'DER-encode-value
                                  "missing field in Sequence value\n  value: ~e\n  field: ~s~a"
                                  name v
                                  (if (pair? lvs)
                                      (format "\n  got: ~s" (car (car lvs)))
                                      ""))])])]))]
       [_ (error 'DER-encode-value "bad value for Sequence\n  value: ~e" v)])]
    [(list _ ...)
     (unless (= (length v) (length elts))
       (error 'DER-encode-value "wrong number of elements for Sequence\n  value: ~e" v))
     (for/list ([v* (in-list v)]
                [elt (in-list elts)])
       (match elt
         [(element-type name tag* type* option)
          (DER-encode type* v* tag*)]))]
    [_
     (error 'DER-encode-value "bad value for Sequence\n  value: ~e" v)]))

;; DER-encode-set* : (listof ElementType) Any -> (listof (U Bytes #f))
(define (DER-encode-set* elts v)
  (define lvs
    (match v
      [(list 'set (and lvs (list (list l v) ...))) lvs]
      [_ (error 'DER-encode-value "bad value for Set type\n  value: ~e" v)]))
  (for/list ([elt (in-list elts)])
    (match elt
      [(element-type name tag* type* option)
       (define default
         (match option [(list 'default default) default] [_ #f]))
       (cond [(assq name lvs)
              => (lambda (lv)
                   (define v* (cadr lv))
                   (if (equal? v* default)
                       #f
                       (DER-encode type* v* tag*)))]
             [(equal? option '(optional))
              #f]
             [default
               ;; Don't encode default
               #f]
             [else
              (error 'DER-encode-value "no value for Set field\n  field: ~s\n  value: ~e"
                     name v)])])))

;; ============================================================

(define (DER-decode type b)
  (DER-decode-frame type (unwrap-der b)))

(define (DER-decode-frame type frame)
  (eprintf "** decoding ~e\n" type)
  (match-define (der-frame tagclass p/c tagn c) frame)
  (let loop ([type type] [alt-types null] [check-whole-tag? #t])
    ;; check-type : Base-Type -> Void
    (define (check-type base-type)
      (define te (type->tag-entry base-type))
      (unless te (error 'DER-decode "unknown base type\n  type: ~s" base-type))
      (when check-whole-tag?
        (unless (equal? tagclass 'universal)
          (error 'DER-decode "tag class mismatch\n  expected: ~s\n  decoded: ~s"
                 'universal tagclass))
        (unless (equal? tagn (tag-entry-tagn te))
          (error 'DER-decode "tag number mismatch\n  expected: ~s\n  decoded: ~s"
                 (tag-entry-tagn te) tagn)))
      (unless (equal? p/c (tag-entry-p/c te))
        (error 'DER-decode "primitive vs constructed mismatch\n  expected: ~s\n  decoded: ~s"
               (tag-entry-p/c te) p/c)))

    (define (decode-value)
      (DER-decode-value type c alt-types))

    (match type
      [(asn1-type:base base-type)
       (check-type base-type)
       (decode-value)]
      [(asn1-type:sequence _)
       (check-type 'SEQUENCE)
       (decode-value)]
      [(asn1-type:sequence-of _)
       (check-type 'SEQUENCE)
       (decode-value)]
      [(asn1-type:set _)
       (check-type 'SET)
       (decode-value)]
      [(asn1-type:set-of type*)
       (check-type 'SET)
       (decode-value)]
      [(asn1-type:choice elts)
       (let choice-loop ([elts elts])
         (match elts
           [(cons (and elt0 (element-type _ _ et-type _)) rest-elts)
            (if (tag-matches elt0 frame)
                (loop et-type (cons type alt-types) #f)
                (choice-loop rest-elts))]
           [_ (error 'DER-decode "tag does not match any alternative in Choice")]))]
      [(asn1-type:defined name promise)
       (loop (force promise) (cons type alt-types) check-whole-tag?)])))

;; tag-matches : Element-Type DER-Frame -> Boolean
;; Checks class and tag number for match; FIXME: check p/c
(define (tag-matches elt frame)
  ;; (match-define (element-type _ et-tag et-type _) elt)
  (match-define (der-frame f-tagclass f-p/c f-tagn _) frame)
  (define et-tags (type->tags elt))
  (for/or ([et-tag (in-list et-tags)])
    ;; FIXME: need to consider p/c !!!
    (and (equal? f-tagclass (car et-tag))
         (equal? f-tagn (cadr et-tag)))))

(define (DER-decode-value type c [alt-types null])
  (define hooks (DER-decode-hooks))
  (define pre-hook
    (or (search-hooks 'pre alt-types hooks)
        (get-hook 'pre type hooks)))
  (if pre-hook
      (let ([pre-hook-f (caddr pre-hook)])
        (pre-hook-f type c))
      (let* ([post-hook
              (or (search-hooks 'post alt-types hooks)
                  (get-hook 'post type hooks))]
             [v (DER-decode-value* type c)])
        (if post-hook
            (let ([post-hook-f (caddr post-hook)])
              (post-hook-f type v))
            v))))

(define (DER-decode-value* type c)
  (match type
    [(asn1-type:base base-type)
     (DER-decode-base* base-type c)]
    [(asn1-type:sequence elts)
     (DER-decode-sequence* elts (unwrap-ders c))]
    [(asn1-type:sequence-of type*)
     (for/list ([frame (in-list (unwrap-ders c))])
       (DER-decode-frame type* frame))]
    [(asn1-type:set elts)
     (DER-encode-set* elts c)]
    [(asn1-type:set-of type*)
     (for/list ([frame (in-list (unwrap-ders c))])
       (DER-decode-frame type* frame))]
    [(asn1-type:choice elts)
     (error 'DER-decode-value "internal error: bad type\n  type: ~e" type)]
    [(asn1-type:defined name promise)
     (error 'DER-decode-value "internal error: bad type\n  type: ~e" type)]))

(define (DER-decode-base* base-type c)
  (define (bad-value [expected #f])
    (error 'DER-decode-value
           "bad value for type\n  type: ~s\n  value: ~e~a"
           base-type c
           (if expected (format "\n  expected: ~a" expected) "")))
  (case base-type
    [(INTEGER)
     (eprintf "c = ~s\n" c)
     (base256->signed c)]
    [(BIT-STRING)
     (decode-bit-string c)]
    [(OCTET-STRING)
     c]
    [(NULL)
     #f]
    [(OBJECT-IDENTIFIER)
     (decode-object-identifier c)]
    ;; Sequence[Of], Set[Of]
    [(PrintableString)
     (decode-printable-string c)]
    ;; T61String
    [(IA5String)
     (decode-ia5string c)]
    ;; UTCTime
    [else (error 'DER-decode-value "unsupported base type\n  type: ~s" base-type)]))

;; DER-decode-sequence* : (listof ElementType) (listof Frame)
;;                     -> (cons 'sequence (listof (list Symbol Any)))
(define (DER-decode-sequence* elts frames)
  (cons 'sequence
    (let loop ([elts elts] [frames frames])
      (match elts
        [(cons (and elt0 (element-type et-name et-tag et-type et-option)) rest-elts)

         ;; current element is missing; try to skip
         (define (try-skip rest-frames)
           (match et-option
             ['(optional)
              (loop rest-elts rest-frames)]
             [(list 'default default-value)
              (cons (list et-name default-value)
                    (loop rest-elts rest-frames))]
             [#f
              (error 'DER-decode-value
                     "missing field in encoded Sequence\n  field: ~s"
                     et-name)]))

         (match frames
           [(cons (and frame0 (der-frame f-tagclass f-p/c f-tagn f-c)) rest-frames)
            (cond [(tag-matches elt0 frame0)
                   (cons (list et-name (DER-decode-frame et-type frame0))
                         (loop rest-elts rest-frames))]
                  [else (try-skip rest-frames)])]
           ['()
            (try-skip '())])]
        ['()
         (if (null? frames)
             null
             (error 'DER-decode-value
                    "leftover components in encoded Sequence"))]))))

;; DER-decode-set* : (listof ElementType) (listof Frame)
;;                -> (cons 'set (listof (list Symbol Any)))
(define (DER-decode-set* elts frames)
  (cons 'set
    (let loop ([elts elts] [frames frames])
      (match elts
        [(cons (and elt0 (element-type et-name _ et-type et-option)) rest-elts)
         (cond [(for/first ([frame (in-list frames)]
                            #:when (tag-matches elt0 frame))
                  frame)
                => (lambda (frame0)
                     (cons (list et-name (DER-decode-frame et-type frame0))
                           (loop rest-elts (remq frame0 frames))))]
               [else
                ;; current element is missing; try to skip
                (match et-option
                  ['(optional)
                   (loop rest-elts frames)]
                  [(list 'default default-value)
                   (cons (list et-name default-value)
                         (loop rest-elts frames))]
                  [#f
                   (error 'DER-decode-value
                          "missing field in encoded Set\n  field: ~s" et-name)])])]
        ['()
         (if (null? frames)
             null
             (error 'DER-decode-value
                    "leftover components in encoded Set"))]))))
