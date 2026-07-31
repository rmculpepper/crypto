;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

;; Interfaces and (method) implementations

;; Restrictions and limitations:
;; - dispatch on first positional argument
;; - sub-interface cannot "override" super-interface methods
;; - `augment` methods not supported, since call not tied to `this`
;; - interface contracts cannot refer to interface members

;; TODO:
;; - add ordering constraints, eg import with #:prereq
;; - add inspector, add reflective operations
;;   - util to check no unimplemented methods (except given list)
;; - add provide expander?
;; - make impl/c collapsible?

#lang racket/base
(require (for-syntax racket/base
                     racket/match
                     racket/syntax
                     racket/struct-info
                     syntax/parse
                     syntax/datum
                     syntax/id-table
                     syntax/transformer)
         racket/contract
         racket/list
         racket/match)
(provide define-interface
         interface?
         unimplemented?
         interface->predicate
         make-generic
         bundle
         make-bundle
         method-properties
         define/invoke-bundles
         dynamic-invoke-bundles
         define-struct-abbrevs)

(module util racket/base
  (require racket/match racket/list)
  (provide (all-defined-out))

  ;; closure : (Listof X) (Listof Y) (X -> (Listof X))
  ;;        -> (values (Listof X) (Hasheq X (Listof Y)))
  ;; Given initial xs and corresponding ys, returns xs closed under get-next,
  ;; along with mapping of x to originating y. BFS order.
  (define (closure xs ys get-next)
    (define (add y ys) (if (memq y ys) ys (cons y ys)))
    (define (loop xys seen acc nextxyss)
      (match xys
        [(cons (cons x y) xys)
         (define seen* (hash-update seen x (lambda (ys) (add y ys)) null))
         (cond [(hash-has-key? seen x)
                (loop xys seen* acc nextxyss)]
               [else
                (define acc* (cons x acc))
                (define nextxs (get-next x))
                (define nextxys (map (lambda (x) (cons x y)) nextxs))
                (define nextxyss* (cons nextxys nextxyss))
                (loop xys seen* acc* nextxyss*)])]
        ['()
         (cond [(pair? nextxyss)
                (loop (append* (reverse nextxyss)) seen acc null)]
               [else (values (reverse acc) seen)])]))
    (loop (map cons xs ys) (hash) null null)))

(require (submod "." util)
         (for-syntax (submod "." util)))

;; contract for checking implementations of an interface member
(define (impl/c vname ctc)
  (define ctc-get-proj (get/build-late-neg-projection ctc))
  (define important (format "~a (impl)" vname))
  (define message (format "the ~s implementation for" vname))
  (make-contract
   #:name (list 'impl/c (list 'quote vname) (contract-name ctc))
   #:first-order (contract-first-order ctc)
   #:late-neg-projection
   (lambda (blame)
     (define swapped-blame
       ;; #:important resets blame to "produced"!
       (blame-add-context blame message
                          #:important important #:swap? #t))
     (define proj (ctc-get-proj swapped-blame))
     (lambda (v neg-party)
       (proj v neg-party)))
   #:list-contract? (list-contract? ctc)))

(begin-for-syntax
  (define-syntax-class body-term
    #:attributes () #:commit #:opaque
    (pattern _:expr)))


;; ============================================================
;; Interfaces

;; ----------------------------------------
;; Run time

;; RtInterface:
(struct rtif
  (name         ;; Symbol
   uid          ;; InterfaceKey
   supers       ;; (Listof RtInterface)
   vnames       ;; (Listof Symbol)
   pubnames     ;; (Listof Symbol) -- subset of vnames
   in-ctcv      ;; (Vectorof (U Contract #f)) -- used to check impls
   out-ctcv     ;; (Vectorof (U Contract #f))
   fallbacks    ;; VarHash
   vprop        ;; (StructTypeProperty #:in (StructType -> VarHash) #:out VarVector)
   vprop?       ;; (Any -> Boolean)
   vprop-ref    ;; (vprop? -> VarVector)
   )
  #:property prop:custom-write
  (lambda (self out mode)
    (fprintf out "#<interface:~.s>" (rtif-name self))))

(define (interface? v) (rtif? v))

;; InterfaceKey = Symbol, unique to interface (not interned)
;; VarHash = (Hasheq Symbol Value)
;; VarVector = (vector VarHash Value ...)

;; rtifs-closure : (Listof RtInterface) -> (Listof RtInterface)
(define (rtifs-closure ifcs)
  (define-values (ifcs* _h) (closure ifcs ifcs rtif-supers))
  ifcs*)

;; create-rtif : Symbol Symbol (Listof Symbol) (Listof Symbol)
;;               (Vectorof (U Contract #f)) DeriveProps VarHash
;;            -> RtInterface
(define (create-rtif iname uid supers vnames pubnames ctcv derives fallbacks)
  (define len (length vnames))
  (define (vprop-guard in-val st-info)
    (define super-stype (list-ref st-info 6))
    (define vh (in-val super-stype))
    (apply vector-immutable
           vh
           (for/list ([vname (in-list vnames)])
             (hash-ref vh vname))))
  (define in-ctcv
    (apply vector-immutable
           (for/list ([ctc (in-vector ctcv)] [vname (in-list vnames)])
             (and ctc (impl/c vname ctc)))))
  (define-values (vprop vprop? vprop-ref)
    (make-struct-type-property iname vprop-guard derives))
  (define fallbacks*
    (for/fold ([vh (hasheq)]) ([vname (in-list vnames)])
      (hash-set vh vname (hash-ref fallbacks vname (lambda () (unimplemented iname vname))))))
  (for ([key (in-hash-keys fallbacks)] #:when (not (hash-has-key? fallbacks* key)))
    (error 'interface "unexpected key in fallbacks\n  key: ~e\n  interface: ~e"
           key iname))
  (rtif iname uid supers vnames pubnames in-ctcv ctcv fallbacks* vprop vprop? vprop-ref))

;; rtif-lookup-definer : RtInterface Symbol -> (U RtInterface #f)
(define (rtif-lookup-definer ifc seek-name)
  (let loop ([ifc ifc])
    (cond [(memq seek-name (rtif-vnames ifc)) ifc]
          [else (ormap loop (rtif-supers ifc))])))

;; rtif-get-stype-vh : RtInterface (U StructType #f) -> VarHash
(define (rtif-get-stype-vh ifc stype)
  (define vprop? (rtif-vprop? ifc))
  (define vprop-ref (rtif-vprop-ref ifc))
  (cond [(vprop? stype) (vector-ref (vprop-ref stype) 0)]
        [else (rtif-fallbacks ifc)]))

(struct unimplemented (iname vname)
  #:property prop:procedure
  (make-keyword-procedure
   (lambda (kws kwargs self . args)
     (match-define (unimplemented iname vname) self)
     (error vname "not implemented\n  interface: ~a" iname))
   (lambda (self . args)
     (match-define (unimplemented iname vname) self)
     (error vname "not implemented\n  interface: ~a" iname))))

(define (interface->predicate ifc [vname #f])
  (define who 'interface->predicate)
  (unless (interface? ifc)
    (raise-argument-error who "interface?" ifc))
  (unless (or (eq? vname #f) (symbol? vname))
    (raise-argument-error who "(or/c #f symbol?)" vname))
  (define vprop? (rtif-vprop? ifc))
  (cond [vname
         (define difc (rtif-lookup-definer ifc vname))
         (unless difc
           (error who "~a\n  interface: ~e\n  name: ~e"
                  "name not found in interface" ifc vname))
         (define dvprop-ref (rtif-vprop-ref difc))
         (define (interface-predicate v)
           (and (vprop? v)
                (let ([vh (vector-ref (dvprop-ref v) 0)])
                  (not (unimplemented? (hash-ref vh vname #f))))))
         interface-predicate]
        [else vprop?]))

(define fallbacks/c (hash/c symbol? any/c))

;; ----------------------------------------
;; Compile time

(begin-for-syntax
  ;; CtInterface:
  (struct ctif
    (name       ;; Identifier
     uid        ;; InterfaceKey
     rt         ;; Id[RtInterface]
     supers     ;; (Listof CtInterface)
     vnames     ;; (Listof Symbol)
     )
    #:property prop:procedure
    (lambda (self stx)
      ((make-variable-like-transformer (ctif-rt self)) stx)))

  (define (create-ctif info-stx)
    (define/with-syntax (iname rtname (super-id ...) (vname ...)) info-stx)
    (define uid (string->uninterned-symbol (symbol->string (syntax-e #'iname))))
    ;; FIXME: check no duplicate names
    (define supers (map syntax-local-value (datum (super-id ...))))
    (let ()
      (define seen (make-hasheq))
      (define-values (all-supers super-h) (closure supers supers ctif-supers))
      (for ([ifc (in-list all-supers)])
        (define oifc (car (hash-ref super-h ifc)))
        (for ([vname (in-list (ctif-vnames ifc))])
          (cond [(hash-ref seen vname #f)
                 => (lambda (oifc1)
                      (raise-syntax-error
                       #f "duplicate name in interface" #'iname #f
                       (list (ctif-name oifc1) (ctif-name oifc))))]
                [else (hash-set! seen vname oifc)])))
      (for ([vname (in-list (datum (vname ...)))])
        (cond [(hash-ref seen (syntax-e vname) #f)
               => (lambda (src1)
                    (raise-syntax-error
                     #f "duplicate name in interface" #'iname vname))]
              [else (hash-set! seen vname #t)])))
    (ctif #'iname uid #'rtname supers (syntax->datum #'(vname ...))))

  (define-syntax-class interface-ref
    #:attributes (value)
    (pattern (~var n (static ctif? "name defined as interface"))
             #:attr value (datum n.value))))

(define-syntax (create-rtif-from-ctif stx)
  (syntax-parse stx
    [(_ ifc:interface-ref pubnames:expr ctcv:expr fallbacks:expr derives:expr)
     (define ct (datum ifc.value))
     (match-define (ctif iname uid _ supers vnames) (datum ifc.value))
     (with-syntax ([iname iname] [uid uid] [vnames vnames])
       (with-syntax ([(super-ifcvar ...) (map ctif-rt supers)])
         #`(create-rtif (quote iname) (quote uid) (list super-ifcvar ...)
                        (quote vnames) pubnames ctcv derives fallbacks)))]))

(define-syntax (define-interface stx)
  (define-syntax-class var-decl
    #:attributes (name src ctc get-public?)
    (pattern name:id
             #:with src #'name
             #:attr ctc #f
             #:attr get-public? (lambda (all-public?) all-public?))
    (pattern [name:id
              (~alt (~optional (~seq #:dynamic-public (~bind [public? #t]))
                               #:name "dynamic-public clause")
                    (~optional (~seq #:contract ctc:expr)
                               #:name "contract clause"))
              ...]
             #:with src (datum->syntax #f (list #'name '....) this-syntax)
             #:attr get-public? (lambda (all-public?) (or all-public? (datum public?)))))
  (define-splicing-syntax-class maybe-super
    (pattern (~seq #:super (super:interface-ref ...)))
    (pattern (~seq) #:with (super ...) null))
  (define-splicing-syntax-class derive-clause
    #:attributes (kvpair)
    (pattern (~seq #:derive-property prop prop-value:expr)
             #:declare prop (expr/c #'struct-type-property?)
             #:with kvpair #'(cons prop.c (lambda (v) prop-value))))
  (syntax-parse stx
    [(_ iname:id s:maybe-super
        (d:var-decl ...)
        (~alt
         (~optional (~seq #:predicate predicate:id)
                    #:name "predicate clause")
         (~optional (~seq #:dynamic-public (~bind [all-public? #t]))
                    #:name "dynamic-public clause")
         (~optional (~seq #:fallbacks (~var fallbacks (expr/c #'fallbacks/c)))
                    #:name "fallbacks clause")
         (~optional (~seq #:generics-prefix gprefix:id)
                    #:name "generics prefix clause")
         (~optional (~seq #:no-generics (~bind [no-generics? #t]))
                    #:name "no-generics clause")
         dc:derive-clause)
        ...)
     (when (and (datum gprefix) (datum no-generics?))
       (raise-syntax-error #f "cannot use both #:generics-prefix and #:no-generics" stx))
     (define public?s
       (for/list ([get-public? (in-list (datum (d.get-public? ...)))])
         (get-public? (datum all-public?))))
     (define/with-syntax iname?
       (or (datum predicate) (format-id #'iname "~a?" #'iname)))
     (define/with-syntax (rtname) (generate-temporaries #'(iname)))
     (define/with-syntax (vname ...) #'(d.name ...))
     (define/with-syntax (pubname ...)
       (for/list ([vname (in-list (datum (vname ...)))]
                  [public? (in-list public?s)]
                  #:when public?)
         vname))
     (define/with-syntax (gname ...)
       (cond [(datum gprefix)
              (for/list ([vname (in-list (datum (vname ...)))])
                (format-id vname "~a~a" #'gprefix vname))]
             [else #'(vname ...)]))
     (define/with-syntax (generic-expr ...)
       #'((make-generic* rtname (quote vname) (quote gname) #f #t) ...))
     (define/with-syntax (ctcname ...) (generate-temporaries (datum (vname ...))))
     (define/with-syntax generic-defs
       (cond [(datum no-generics?)
              #'(begin)]
             [(not (ormap values (datum (d.ctc ...))))
              #'(begin (define gname generic-expr) ...)]
             [(eq? (syntax-local-context) 'module)
              (define/with-syntax (gname* ...) (generate-temporaries #'(gname ...)))
              (define/with-syntax (index ...)
                (for/list ([i (in-naturals)] [gname (in-list (datum (gname ...)))]) i))
              (define/with-syntax (blame-id ...)
                #;(datum (gname ...))
                (for/list ([gname (in-list (datum (gname ...)))])
                  (define bsym (string->symbol (format "~a (generic)" (syntax-e gname))))
                  (datum->syntax #f bsym gname)))
              #'(begin
                  (~? (begin (define gname* generic-expr)
                             (define-module-boundary-contract gname
                               gname* d.ctc
                               #:pos-source (quote (interface iname))
                               #:name-for-blame blame-id))
                      (define gname generic-expr))
                  ...)]
             [else
              (define/with-syntax ((ctc-gname ctc-expr) ...)
                (for/list ([index (in-naturals 0)]
                           [gname (in-list (datum (gname ...)))]
                           [ctc (in-list (datum (d.ctc ...)))]
                           #:when ctc)
                  (with-syntax ([index index])
                    (list gname #'(vector-ref (rtif-out-ctcv rtname) (quote index))))))
              #'(with-contract #:region interface iname
                  ([ctc-gname ctc-expr] ...)
                  (define gname generic-expr) ...)]))
     #'(begin
         (define-syntax iname
           (create-ctif (quote-syntax (iname rtname (s.super ...) (vname ...)))))
         (define (iname? v) ;; define early, available for ctcs
           ((rtif-vprop? rtname) v))
         (define rtname
           (let ([ctcname (~? (coerce-contract 'define-interface d.ctc) #f)] ...)
             (create-rtif-from-ctif iname (quote (pubname ...))
                                    (vector-immutable ctcname ...)
                                    (~? fallbacks.c (hasheq))
                                    (list dc.kvpair ...))))
         generic-defs)]))

;; ============================================================
;; Generic Functions

;; make-generic : RtInterface Symbol -> (Instance Any ... -> Any)
(define (make-generic ifc name)
  (unless (interface? ifc) (raise-argument-error 'make-generic "interface?" ifc))
  (unless (symbol? name) (raise-argument-error 'make-generic "symbol?" name))
  (or (make-generic* ifc name name #t #f)
      (error/no-method 'make-generic ifc name)))

;; make-generic* : RtInterface Symbol Boolean Boolean
;;              -> (Instance Any ... -> Any) or #f
(define (make-generic* ifc seek-name name ctc? allow-private?)
  (let loop ([ifc ifc])
    (or (for/or ([vname (in-list (rtif-vnames ifc))]
                 [index (in-naturals 1)]
                 [ctc (in-vector (rtif-out-ctcv ifc))]
                 #:when (and (eq? vname seek-name)
                             (or allow-private?
                                 (memq seek-name (rtif-pubnames ifc)))))
          (define iname (rtif-name ifc))
          (define vprop? (rtif-vprop? ifc))
          (define vprop-ref (rtif-vprop-ref ifc))
          (define (get-method obj)
            (unless (vprop? obj)
              (raise-argument-error name (format "~a?" iname) obj))
            (vector-ref (vprop-ref obj) index))
          (define proc
            (make-keyword-procedure
             (lambda (kws kwargs obj . args)
               (keyword-apply (get-method obj) kws kwargs obj args))
             (procedure-rename
              (lambda (obj . args)
                (apply (get-method obj) obj args))
              name)))
          (if (and ctc? ctc)
              (let ([pos-party (list 'interface (rtif-name ifc))])
                (contract ctc proc pos-party 'make-generic
                          (format "~a (generic)" name) #f))
              proc))
        (ormap loop (rtif-supers ifc)))))

(define (error/no-method who ifc name)
  (error who
         (string-append "no dynamic-public member found"
                        "\n  interface: ~e\n  name: ~e")
         ifc name))


;; ============================================================
;; Bundles

;; Linkage = (Hash InterfaceKey (Box VarHash))
;; LinkageKey = (cons InterfaceKey Tag)
;; Tag = (Listof Symbol)

;; TaggedInterface = (cons RtInterface Tag)
;; Two tags have special significance:
;; - '() -- default; exports with empty tag are bound to struct-type-properties
;; - '(super) -- reserved for importing super-struct or fallbacks implementation
;;               disallowed as export; automatically initialized by linker
;;               note: import super allowed even if no export to ifc in bundle

(define (tagged-interface? v)
  (and (pair? v) (rtif? (car v)) (list? (cdr v)) (andmap symbol? (cdr v))))

(define (tagged-interface->linkage-key ti)
  (match ti [(cons ifc tag) (cons (rtif-uid ifc) tag)]))

(define (tagged-interfaces-closure tis)
  (define (ti-next ti)
    (match-define (cons ifc tag) ti)
    (map (lambda (ifc) (cons ifc tag)) (rtif-supers ifc)))
  (define-values (closed-tis _h) (closure tis tis ti-next))
  closed-tis)

(define (tagged-interface->string ti)
  ;; also accepts symbol in car
  (cond [(null? (cdr ti)) (format "~.s" (car ti))]
        [else (format "~.s #:tag (~.s)" (car ti) (cdr ti))]))

;; Bundle = Bundle1 | (compound-bundle (Listof BundlePart))
(define (bundle? v) (or (bundle1? v) (compound-bundle? v)))

(struct compound-bundle (parts)
  #:reflection-name 'bundle)
(struct bundle1
  (exports    ;; (Listof TaggedInterface), closed
   imports    ;; (Listof TaggedInterface), closed
   init!      ;; Linkage -> Void
   ) #:reflection-name 'bundle)

;; flatten-bundles : (Listof Bundle) -> (Listof Bundle1)
(define (flatten-bundles bs)
  (append* (for/list ([b (in-list bs)])
             (match b
               [(compound-bundle bs) (flatten-bundles bs)]
               [(? bundle1?) (list b)]))))

(define listof-bundle/c (listof bundle?))

;; ----------------------------------------

;; make-bundle : #:{export,import} (Listof TaggedInterface) (Lookup -> NameHash)
;;            -> Bundle
;; where Lookup = (TaggedInterface Symbol -> Any)
(define (make-bundle make-table
                     #:export [exports0 null]
                     #:import [imports0 null]
                     #:link [linked-bs null])
  (define exports1 (convert-tagged-interfaces exports0))
  (unless exports1
    (raise-argument-error 'make-bundle "(listof tagged-interface?)" exports0))
  (define imports1 (convert-tagged-interfaces imports0))
  (unless imports1
    (raise-argument-error 'make-bundle "(listof tagged-interface?)" imports0))
  (unless (and (list? linked-bs) (andmap bundle? linked-bs))
    (raise-argument-error 'make-bundle "(listof bundle?)" linked-bs))
  (unless (and (procedure? make-table) (procedure-arity-includes? make-table 1))
    (raise-argument-error 'make-bundle "(procedure-arity-includes/c 1)" make-table))
  (define exports (tagged-interfaces-closure exports1))
  (define imports (tagged-interfaces-closure imports1))
  (define (init! linkage)
    (define lookup* ;; mutated
      (make-linkage-lookup linkage))
    (define (lookup ifc seek-name)
      (lookup* ifc seek-name))
    (define nh (make-table lookup))
    (unless (and (hash? nh) (for/and ([key (in-hash-keys nh)]) (symbol? key)))
      (error 'make-bundle "procedure result is not hash with symbol keys\n  result: ~e" nh))
    (when #t
      (for ([name (in-hash-keys nh)])
        (unless (for/or ([export (in-list exports)])
                  (memq name (rtif-vnames (car export))))
          (error 'make-bundle "unexpected key in result\n  key: ~e" name))))
    (set! lookup*
          (lambda (ifc seek-name)
            (error 'lookup "~a\n  interface: ~e\n  name: ~e"
                   "cannot call after linking is complete" ifc seek-name)))
    (for ([export (in-list exports)])
      (define lkey (tagged-interface->linkage-key export))
      (define super-lkey (cons (car lkey) '(super)))
      (define super-vh (unbox (hash-ref linkage super-lkey)))
      (define export-box (hash-ref linkage lkey))
      (set-box! export-box
                (for/fold ([vh super-vh])
                          ([vname (in-list (rtif-vnames (car export)))]
                           #:when (hash-has-key? nh vname))
                  (hash-set vh vname (hash-ref nh vname))))))
  (define b1 (bundle1 exports imports init!))
  (make-bundle* b1 linked-bs))

;; make-linkage-lookup : Linkage -> TaggedInterface Symbol -> Any
(define ((make-linkage-lookup linkage) ti0 seek-name)
  (define ti1 (convert-tagged-interface ti0))
  (unless ti1 (raise-argument-error 'lookup "tagged-interface?" ti0))
  (unless (symbol? seek-name) (raise-argument-error 'lookup "symbol?" seek-name))
  (match-define (cons ifc0 tag) ti0)
  (define difc (rtif-lookup-definer ifc0 seek-name))
  (cond [difc
         (define linkage-key (cons (rtif-uid difc) tag))
         (cond [(hash-ref linkage linkage-key #f)
                => (lambda (vhbox)
                     (unless (unbox vhbox)
                       (error 'lookup "~a\n  tagged interface: ~e"
                              "imported interface not initialized" ti0))
                     (hash-ref (unbox vhbox) seek-name))]
               [else (error 'lookup "~a\n  tagged interface: ~e"
                            "interface not imported" ti0)])]
        [else (error 'lookup "~a\n  interface: ~e\n  name: ~e"
                     "not found in interface" ifc0 seek-name)]))

(define (make-bundle* b1 bs)
  (if (null? bs) b1 (compound-bundle (append bs (list b1)))))

(define (convert-tagged-interfaces vs)
  (and (list? vs)
       (let ([tis (map convert-tagged-interface vs)])
         (and (andmap values tis) tis))))
(define (convert-tagged-interface v)
  (match v
    [(? interface? ifc) (list ifc)]
    [(cons (? interface?) (list (? symbol?) ...)) v]
    [_ #f]))

;; ----------------------------------------

(begin-for-syntax
  (struct impexp (ostx ifc tag prefix))

  (define-syntax-class import/export-spec
    #:attributes (ast)
    (pattern ifc:interface-ref
             #:attr ast
             (let ([prefix (format-id #'ifc "")])
               (impexp this-syntax (datum ifc.value) '() prefix)))
    (pattern [ifc:interface-ref
              (~alt
               (~optional t:tag-clause #:name "tag clause")
               (~optional (~seq #:prefix prefix:id)
                          #:name "prefix clause"))
              ...]
             #:attr ast
             (let ([tag (or (datum t.tag) null)]
                   [prefix (or (datum prefix) (format-id #'ifc ""))])
               (impexp this-syntax (datum ifc.value) tag prefix))))

  (define-splicing-syntax-class tag-clause
    #:attributes (tag)
    (pattern (~seq #:super) #:attr tag '(super))
    (pattern (~seq #:tag (t:id ...)) #:attr tag (syntax->datum #'(t ...))))

  (define (impexp=? ie1 ie2)
    (match-define (impexp _ ifc1 tag1 prefix1) ie1)
    (match-define (impexp _ ifc2 tag2 prefix2) ie2)
    (and (eq? ifc1 ifc2) (equal? tag1 tag2)
         (bound-identifier=? prefix1 prefix2)))

  (define (check-impexps ies stx whats)
    (define ifcs (map impexp-ifc ies))
    (define-values (_ifcs ifc=>ies) (closure (map impexp-ifc ies) ies ctif-supers))
    (for/list ([(ifc ies) (in-hash ifc=>ies)])
      (define ie (car ies))
      (for ([ie2 (in-list (cdr ies))])
        (unless (impexp=? ie ie2)
          (raise-syntax-error
           #f (format "incompatible ~a\n  interface: ~e" whats (syntax-e (ctif-name ifc)))
           stx #f (list (impexp-ostx ie) (impexp-ostx ie2)))))
      (cons ifc ie)))

  (struct bctx (ostxs tis vnamess localname=>vname vname=>ref [localname=>t #:mutable]))

  (define (make-bctx einfo-stx)
    (define/with-syntax ((eostx ti-expr eprefix (evname ...)) ...) einfo-stx)
    (define localname=>vname (make-bound-id-table))
    (for ([eprefix (in-list (datum (eprefix ...)))]
          [evnames (in-list (datum ((evname ...) ...)))]
          #:when #t
          [evname (in-list evnames)])
      (define localname (format-id eprefix "~a~a" eprefix evname))
      (bound-id-table-set! localname=>vname localname (syntax-e evname)))
    (define vname=>ref (make-hasheq))
    (bctx (datum (eostx ...)) (datum (ti-expr ...)) (syntax->datum #'((evname ...) ...))
          localname=>vname vname=>ref #f))

  (define (bctx-add-seen! ctx ids)
    (match-define (bctx _ _ _ localname=>vname vname=>ref localname=>t) ctx)
    (for ([id (in-list ids)])
      (cond [(bound-id-table-ref localname=>vname id #f)
             => (lambda (vname) (hash-set! vname=>ref vname id))]
            [else (void)])))

  (define (bctx-exported-var? ctx id)
    (unless (bctx-localname=>t ctx)
      ;; must wait until pass2 to build free-id-table,
      ;; because identifier-binding-symbol may change
      (define localname=>t (make-free-id-table))
      (for ([ref (in-hash-values (bctx-vname=>ref ctx))])
        (free-id-table-set! localname=>t ref #t))
      (set-bctx-localname=>t! ctx localname=>t))
    (define localname=>t (bctx-localname=>t ctx))
    (and (free-id-table-ref localname=>t id #f) #t))

  (void))

(define-syntax (method-properties stx)
  (case (syntax-local-context)
    [(expression)
     #`(bundles->properties
        #:who 'method-properties
        (bundle* #,stx))]
    [else #`(#%expression #,stx)]))

(define-syntax (bundle stx)
  (case (syntax-local-context)
    [(expression)
     #`(bundle* #,stx)]
    [else #`(#%expression #,stx)]))

(define-syntax (bundle* outer-stx)
  (define stx (syntax-parse outer-stx [(_ expr) #'expr]))
  (syntax-parse stx
    [(_ #:link (~var link-bs (expr/c #'listof-bundle/c)))
     #'(compound-bundle link-bs.c)]
    [(_ (~alt
         (~optional (~seq #:export (e:import/export-spec ...))
                    #:name "export clause")
         (~optional (~seq #:import (i:import/export-spec ...))
                    #:name "import clause")
         (~optional (~seq #:link (~var link-bs (expr/c #'listof-bundle/c)))
                    #:name "link clause"))
        ...
        body:body-term ...)
     (define eifc+ie-list (check-impexps (datum (~? (e.ast ...) ())) stx "exports"))
     (define iifc+ie-list (check-impexps (datum (~? (i.ast ...) ())) stx "imports"))
     (define/with-syntax ((eti eprefix evnames eostx) ...)
       (for/list ([eifc+ie (in-list eifc+ie-list)])
         (match-define (cons ifc (impexp ostx _ tag prefix)) eifc+ie)
         (list #`(cons #,(ctif-rt ifc) (quote #,tag))
               prefix (ctif-vnames ifc) ostx)))
     (define/with-syntax ((iti iprefix ivnames iostx) ...)
       (for/list ([iifc+ie (in-list iifc+ie-list)])
         (match-define (cons ifc (impexp ostx _ tag prefix)) iifc+ie)
         (list #`(cons #,(ctif-rt ifc) (quote #,tag))
               prefix (ctif-vnames ifc) ostx)))
     #`(make-bundle*
        (bundle1
         (list eti ...) (list iti ...)
         (lambda (linkage)
           (define-names #:lazy iprefix ivnames iti linkage iostx)
           ...
           (let ()
             (define-syntaxes (the-bctx)
               (make-bctx (quote-syntax ((eostx eti eprefix evnames) ...))))
             (bundle-body-wrap the-bctx body) ...
             (#%expression (bundle-body-result the-bctx linkage)))))
        (~? link-bs.c null))]))

(define-syntax (bundle-body-wrap stx)
  (syntax-parse stx
    [(_ ctx-id body)
     (define ctx (syntax-local-value #'ctx-id))
     (define ee (local-expand #'body (syntax-local-context) #f))
     (syntax-parse ee
       #:literal-sets (kernel-literals)
       [(begin ~! form ...)
        #'(begin (bundle-body-wrap ctx-id form) ...)]
       [(define-values ~! (var:id ...) rhs:expr)
        (bctx-add-seen! ctx (syntax->list (syntax-local-introduce #'(var ...))))
        #'(define-values (var ...) (bundle-expr-wrap ctx-id rhs))]
       [(define-syntaxes ~! . _) ee]
       [_ #`(#%expression (bundle-expr-wrap ctx-id #,ee))])]))

(define-syntax (bundle-expr-wrap stx)
  (syntax-parse stx
    [(_ ctx-id e)
     (define ctx (syntax-local-value #'ctx-id))
     (define (loop e)
       (define (loop* es)
         (for-each loop (syntax->list es)))
       (syntax-parse e
         #:literal-sets (kernel-literals)
         [(#%plain-lambda formals e ...)
          (loop* #'(e ...))]
         [(case-lambda [formals e ...] ...)
          (loop* #'(e ... ...))]
         [(if e ...)
          (loop* #'(e ...))]
         [(begin e ...)
          (loop* #'(e ...))]
         [(begin0 e ...)
          (loop* #'(e ...))]
         [(let-values ([vars rhs] ...) body ...)
          (loop* #'(rhs ... body ...))]
         [(letrec-values ([vars rhs] ...) body ...)
          (loop* #'(rhs ... body ...))]
         [(with-continuation-mark e ...)
          (loop* #'(e ...))]
         [(#%plain-app e ...)
          (loop* #'(e ...))]
         [(set! var rhs)
          (when (bctx-exported-var? ctx (syntax-local-introduce #'var))
            (raise-syntax-error #f "attempt to mutate exported variable" e #'var))
          (loop #'rhs)]
         [_ (void)]))
     (define-values (ee opaque)
       (syntax-local-expand-expression #'e))
     (loop ee)
     opaque]))

(define-syntax (bundle-body-result stx)
  (syntax-parse stx
    [(_ ctx-id linkage)
     (define ctx (syntax-local-value #'ctx-id))
     (match-define (bctx eostxs etis evnamess _ vname=>ref _) ctx)
     #`(begin
         #,@(for/list ([eostx (in-list eostxs)]
                       [eti (in-list etis)]
                       [evnames (in-list evnamess)])
              (define/with-syntax ((def-vname def-index def-localname) ...)
                (for/list ([evname (in-list evnames)]
                           [index (in-naturals)]
                           #:when (hash-has-key? vname=>ref evname))
                  (define localname (syntax-local-introduce (hash-ref vname=>ref evname)))
                  (list evname index localname)))
              #`(linkage-set! linkage #,eti (current-contract-region) (quote-syntax #,eostx)
                              '(def-vname ...) '(def-index ...)
                              (list def-localname ...)))
         (void))]))

(define (linkage-set! linkage ti impl-party src-stx vnames vindexes vvalues)
  (define lkey (tagged-interface->linkage-key ti))
  (define super-lkey (cons (car lkey) '(super)))
  (define vhbox (hash-ref linkage lkey))
  (define supervh (unbox (hash-ref linkage super-lkey)))
  (define iname (rtif-name (car ti)))
  (define ctcv (rtif-in-ctcv (car ti)))
  (define ifc-party (list 'interface (rtif-name (car ti))))
  (set-box! vhbox
            (for/fold ([vh supervh])
                      ([vname (in-list vnames)]
                       [vindex (in-list vindexes)]
                       [vvalue (in-list vvalues)])
              (define ctc (vector-ref ctcv vindex))
              (define checked-value
                (cond [(not ctc)
                       vvalue]
                      [else
                       (contract ctc vvalue ifc-party impl-party
                                 #f ;; (format "~a (impl)" vname)
                                 src-stx)]))
              (hash-set vh vname checked-value))))

(define-syntax (define-names stx)
  (syntax-parse stx
    [(_ mode prefix:id (vname:id ...) ti:expr linkage:expr ostx)
     (define/with-syntax (varvar ...)
       (generate-temporaries #'(vname ...)))
     (define/with-syntax (prefixedname ...)
       (for/list ([name (in-list (datum (vname ...)))])
         (format-id #'prefix "~a~a" #'prefix name)))
     (case (syntax->datum #'mode)
       [(#:strict)
        (define/with-syntax (index ...)
          (for/list ([i (in-range (length (datum (vname ...))))]) i))
        #`(begin
            (define-values (varvar ...)
              (let* ([lkey (tagged-interface->linkage-key ti)]
                     [vh (unbox (hash-ref linkage lkey))])
                (apply values
                       (vh-extract vh (car ti) (quote (vname ...))
                                   (current-contract-region) (quote-syntax ostx)
                                   "import"))))
            (define-syntax prefixedname
              (make-variable-like-transformer
               (quote-syntax varvar)))
            ...)]
       [(#:lazy)
        #`(begin
            (define varvar (box #f))
            ...
            (define init! ;; mutated
              (let* ([lkey (tagged-interface->linkage-key ti)]
                     [vhbox (hash-ref linkage lkey)])
                (lambda (who)
                  (vh-init! who ti (current-contract-region) (quote-syntax ostx)
                            vhbox '(vname ...) (list varvar ...))
                  (set! init! #f))))
            (define-syntax prefixedname
              (make-variable-like-transformer
               (quote-syntax
                (begin (when init! (init! (quote prefixedname)))
                       (unbox varvar)))))
            ...)])]))

(define (vh-extract vh ifc vnames neg-party src-stx what)
  (define ctcv (rtif-out-ctcv ifc))
  (define pos-party (list 'interface (rtif-name ifc)))
  (define src-stx (quote-syntax ostx))
  (for/list ([vname (in-list vnames)]
             [ctc (in-vector ctcv)])
    (define v (hash-ref vh vname))
    (cond [ctc
           (define bname (format "~s (~a)" vname what))
           (contract ctc v pos-party neg-party bname src-stx)]
          [else v])))

(define (vh-init! who ti neg-party src-stx vhbox vnames varboxes)
  (define pos-party (list 'interface (rtif-name (car ti))))
  (define ctcv (rtif-out-ctcv (car ti)))
  (unless (unbox vhbox)
    (error who "import not initialized\n  import: ~a"
           (tagged-interface->string ti)))
  (define vh (unbox vhbox))
  (for ([vname (in-list vnames)]
        [varbox (in-list varboxes)]
        [ctc (in-vector ctcv)])
    (define v (hash-ref vh vname))
    (define v*
      (cond [ctc
             (define bname (format "~s (import)" vname))
             (contract ctc v pos-party neg-party bname src-stx)]
            [else v]))
    (set-box! varbox v*)))


;; ============================================================
;; Linking Bundles

;; bundles->properties : Bundle1 ...
;;                    -> (Listof (cons VarProp (StructType -> VarHash)))
(define (bundles->properties #:who [who 'bundles->properties] . bs0)
  (unless (and (list? bs0) (andmap bundle? bs0))
    (raise-argument-error who "(listof bundle?)" bs0))
  (define bs (flatten-bundles bs0))
  (define-values (exports linkage initialize-supers!)
    (bundles-prepare-linkage who bs))
  (define (initialize! stype) ;; mutated
    (initialize-supers! stype)
    (run-bundles bs linkage)
    (set! initialize! void))
  (for/list ([export (in-list exports)] #:when (null? (cdr export)))
    (define ifc (car export))
    (define uid (rtif-uid ifc))
    (cons (rtif-vprop ifc)
          (lambda (super-stype)
            (initialize! super-stype)
            (unbox (hash-ref linkage (cons uid '())))))))

;; bundles-prepare-linkage : Symbol (Listof Bundle1)
;;                        -> (values (Listof TaggedInterface)
;;                                   Linkage
;;                                   (StructType/#f -> Void))
(define (bundles-prepare-linkage who bs)
  (define exports (tagged-interfaces-closure (append* (map bundle1-exports bs))))
  (define exported-ifcs (remove-duplicates (map car exports)))
  (define pre-linkage (build-linkage who bs))
  (define imp-super-ifcs (check-linkage who bs pre-linkage))
  (define super-ifcs (remove-duplicates (append exported-ifcs imp-super-ifcs)))
  (define linkage
    (for/fold ([linkage pre-linkage]) ([ifc (in-list super-ifcs)])
      (define super-lkey (cons (rtif-uid ifc) '(super)))
      (hash-set linkage super-lkey (box #f))))
  (define (initialize-supers! stype)
    (for ([ifc (in-list super-ifcs)])
      (define super-vh (rtif-get-stype-vh ifc stype))
      (define super-lkey (cons (rtif-uid ifc) '(super)))
      (set-box! (hash-ref linkage super-lkey) super-vh)))
  (values exports linkage initialize-supers!))

;; build-linkage : Symbol (Listof BundlePart1) -> Linkage*
;; Returns linkage with exports in boxes, must clear after checking.
(define (build-linkage who bs)
  ;; handle-bundle : Bundle1 Linkage -> Linkage
  (define (handle-bundle b linkage)
    (foldl handle-export linkage (bundle1-exports b)))
  ;; handle-export : TaggedInterface Linkage -> Linkage
  (define (handle-export export linkage)
    (define lkey (tagged-interface->linkage-key export))
    (cond [(super-linkage-key? lkey)
           (error who "illegal export with reserved super tag\n  export: ~a"
                  (tagged-interface->string export))]
          [(hash-ref linkage lkey #f)
           => (lambda (link-box)
                (error who "duplicate export: ~a"
                       (tagged-interface->string (unbox link-box))))]
          [else (hash-set linkage lkey (box export))]))
  (foldl handle-bundle (empty-linkage) bs))

;; check-linkage : Symbol (Listof BundlePart1) Linkage* -> (Listof RtInterface)
;; Checks all imports satisfied, except '(super) tagged.
;; Returns interfaces with '(super) imports. Also clears linkage boxes.
(define (check-linkage who bs linkage)
  ;; check-bundle : Bundle1 (Listof RtInterface) -> Void
  (define (check-bundle b acc)
    (foldl check-import acc (bundle1-imports b)))
  ;; check-import : TaggedInterface (Listof RtInterface) -> Void
  (define (check-import import acc)
    (define lkey (tagged-interface->linkage-key import))
    (cond [(super-linkage-key? lkey) (cons (car import) acc)]
          [(hash-has-key? linkage lkey) acc]
          [else (error who "import missing matching export\n  import: ~a"
                       (tagged-interface->string import))]))
  (begin0 (remove-duplicates (foldl check-bundle null bs))
    (for ([b (in-hash-values linkage)]) (set-box! b #f))))

;; empty-linkage : -> Linkage
;; Must use equal? hash because keys are lists.
(define (empty-linkage) (hash))

;; super-linkage-key? : LinkageKey -> Boolean
(define (super-linkage-key? v)
  (match v [(list _ 'super) #t] [_ #f]))

;; run-bundles : (Listof Bundle1) Linkage -> Void
(define (run-bundles bs linkage)
  (for ([b (in-list bs)])
    ((bundle1-init! b) linkage)))

;; ----------------------------------------

(define-syntax (define/invoke-bundles stx)
  (when (eq? (syntax-local-context) 'expression)
    (raise-syntax-error #f "not allowed in expression context" stx))
  (syntax-parse stx
    [(_ (~optional (~seq #:export (e:import/export-spec ...)))
        (~var b (expr/c #'bundle?)) ...)
     (define eifc+ie-list (check-impexps (datum (~? (e.ast ...) ())) stx "exports"))
     (define/with-syntax ((eti eprefix evnames eostx) ...)
       (for/list ([eifc+ie (in-list eifc+ie-list)])
         (match-define (cons ifc (impexp ostx _ tag prefix)) eifc+ie)
         (list #`(cons #,(ctif-rt ifc) (quote #,tag))
               prefix (ctif-vnames ifc) ostx)))
     #'(begin
         (define linkage
           (invoke-bundles* 'define/invoke-bundles (list eti ...) (list b.c ...)))
         (define-names #:strict eprefix evnames eti linkage eostx) ...
         (define-values () (begin (set! linkage #f) (values))))]))

;; invoke-bundles* : Symbol (Listof TaggedInterface) (Listof Bundle) -> Void
;; PRE: binds is closed
(define (invoke-bundles* who binds bs0)
  ;; FIXME: check for var collisions
  (define bs (flatten-bundles bs0))
  (define-values (exports linkage initialize-supers!)
    (bundles-prepare-linkage 'invoke-bundles bs))
  (for ([bind (in-list binds)])
    (define lkey (tagged-interface->linkage-key bind))
    (unless (hash-has-key? linkage lkey)
      (error 'invoke-bundles "~a\n  tagged interface: ~a"
             "tagged interface not exported"
             (tagged-interface->string bind))))
  (initialize-supers! #f)
  (run-bundles bs linkage)
  linkage)

;; dynamic-invoke-bundles : #:bind (Listof TaggedInterface) (Listof Bundle) -> VarHash
(define (dynamic-invoke-bundles #:bind binds0 . bs0)
  (define who 'dynamic-invoke-bundles)
  (define binds1 (convert-tagged-interfaces binds0))
  (unless binds1 (raise-argument-error who "(listof bundle?)" binds0))
  (define binds (tagged-interfaces-closure binds1))
  (for ([b (in-list bs0)])
    (unless (bundle? b) (raise-argument-error who "bundle?" b)))
  (define linkage (invoke-bundles* who binds bs0))
  (for/fold ([h (hasheq)]) ([bind (in-list binds)])
    (define ifc (car bind))
    (define lkey (tagged-interface->linkage-key bind))
    (define bindvh (unbox (hash-ref linkage lkey)))
    (define vnames (rtif-vnames (car bind)))
    (define neg-party 'dynamic-invoke-bundles)
    (define vvalues (vh-extract bindvh ifc vnames neg-party #f "dynamic export"))
    (for/fold ([h h]) ([vname (in-list vnames)] [vvalue (in-list vvalues)])
      (hash-set h vname vvalue))))


;; ============================================================

(define-syntax (define-struct-abbrevs stx)
  (syntax-parse stx
    [(_ (~var sname (static struct-info? "name defined as struct type")))
     (define info (datum sname.value))
     (define infolist (extract-struct-info info))
     (define accessors (list-ref infolist 3))
     (define mutators (list-ref infolist 4))
     (define fields
       (let loop ([info info] [infolist infolist])
         (cond [(struct-field-info? info)
                (define immediate-fields
                  (struct-field-info-list info))
                (define super-name
                  (list-ref infolist 5))
                (define super-info
                  (and (identifier? super-name)
                       (syntax-local-value super-name)))
                (define super-infolist
                  (and super-info (extract-struct-info super-info)))
                (append immediate-fields
                        (loop super-info super-infolist))]
               [else null])))
     (define/with-syntax ((getter accessor) ...)
       (for/list ([accessor (in-list accessors)]
                  [field (in-list fields)]
                  #:when (identifier? accessor))
         (list (format-id stx ".~a" field) accessor)))
     (define/with-syntax ((setter mutator) ...)
       (for/list ([mutator (in-list mutators)]
                  [field (in-list fields)]
                  #:when (identifier? mutator))
         (list (format-id stx ".~a-set!" field) mutator)))
     #'(begin (define-syntax getter
                (make-rename-transformer (quote-syntax accessor)))
              ...)]))


;; ============================================================

(provide equal+hash$
         custom-write$)

(define-interface equal+hash$
  (equal-to?    ;; X X (X X -> Boolean) Boolean -> Boolean
   hashcode     ;; X (X -> Integer) Boolean -> Boolean
   ;; final arg = whether to consider mutable data's current value
   )
  #:derive-property prop:equal+hash
  (list (lambda (self other recur mut-mode?)
          ($equal-to? self other recur mut-mode?))
        (lambda (self recur mut-mode?)
          ($hashcode self recur mut-mode?)))
  #:generics-prefix $)

(define-interface custom-write$
  (custom-write ;; X OutputPort Mode -> Void
   )
  #:derive-property prop:custom-write
  (lambda (self out mode) ($custom-write self out mode))
  #:generics-prefix $)
