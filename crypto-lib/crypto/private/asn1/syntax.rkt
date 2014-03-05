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
;; - (element MaybeName MaybeTag Asn1-Type MaybeOptionalDefault)
(struct element-type (name tag type option) #:transparent)

;; MaybeName is one of
;; - Symbol
;; - #f

;; MaybeTag is one of
;; - (list 'explicit class nat)
;; - (list 'implicit class nat)
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
 (define-splicing-syntax-class name-clause
   (pattern (~seq name:id))
   (pattern (~seq) #:with name #'#f))
 (define-splicing-syntax-class tag-class
   (pattern (~seq #:universal) #:with tclass #''universal)
   (pattern (~seq #:private)   #:with tclass #''private)
   (pattern (~seq #:application) #:with tclass #''application)
   (pattern (~seq) #:with tclass #''context-specific))
 (define-splicing-syntax-class tag-clause
   (pattern (~seq :tag-class #:explicit etag:nat)
            #:with tag #''(explicit tclass etag))
   (pattern (~seq :tag-class #:implicit itag:nat)
            #:with tag #''(implicit tclass itag))
   (pattern (~seq)
            #:with tag #''#f))
 (define-splicing-syntax-class option-clause
   (pattern (~seq #:optional)
            #:with option #''(optional))
   (pattern (~seq #:default v:expr)
            #:with option #'(list 'default v))
   (pattern (~seq)
            #:with option #''#f))

 (define-syntax-class element
   (pattern [:name-clause :tag-clause type :option-clause]
            #:declare type (expr/c #'asn1-type?)
            #:with et #'(element-type 'name tag type.c option))))

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
  (when (and (memq #f tags) (> (length tags) 1))
    (error who "indeterminate tag"))
  (cond [(let loop ([tags tags])
           (and (pair? tags)
                (or (member (car tags) (cdr tags))
                    (loop (cdr tags)))))
         (error who "duplicate tag: ~e" (car tags))])
  ets)

;; FIXME: references to defined types may cause force-cycle problems

;; type->tags : Asn1-Type -> (listof (U Tag #f))
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
     (match tag
       [(cons 'implicit class+tagn)
        (list class+tagn)]
       [(cons 'explicit class+tagn)
        (list class+tagn)]
       [#f
        type->tags type])]))

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

(define (asn1-encode type v [alt-tag #f])
  (match type
    [(asn1-type:base base-type)
     (encode-base-type base-type v alt-tag)]
    [(asn1-type:sequence elts)
     ;; FIXME: handle optional, default, elt/v list mismatch, etc
     (sequence->der
      (for/list ([v* (in-list v)]
                 [elt (in-list elts)])
        (match elt
          [(element-type name tag* type* option)
           (asn1-encode type* v* tag*)]))
      alt-tag)]
    [(asn1-type:sequence-of type*)
     (for/list ([v* (in-list v)])
       (asn1-encode type* v*))]
    [(asn1-type:set elts)
     '...]
    [(asn1-type:set-of type*)
     (for/list ([v* (in-list v)])
       (asn1-encode type* v*))]
    [(asn1-type:choice elts)
     (match-define (list (? symbol? sym) v*) v)
     (match-define (element-type _ tag* type* _)
       (for/or ([elt (in-list elts)])
         (and (eq? (element-type-name elt) sym) elt)))
     (asn1-encode type* v tag*)]
    [(asn1-type:defined name promise)
     (asn1-encode (force promise) v)]))

(define (encode-base-type type v alt-tag)
  ;; FIXME: accept non-bytes for v
  (wrap base-type v alt-tag))
