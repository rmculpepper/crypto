;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

;; Interfaces and (method) implementations

;; Restrictions:
;; - dispatch on first positional argument
;; - sub-interface cannot "override" super-interface methods
;; - `augment` methods not supported, since call not tied to `this`

;; TODO:
;; - add ordering constraints, eg import with #:prereq
;; - add inspector, add reflective operations
;; - add no-generics option

#lang racket/base
(require (for-syntax racket/base
                     racket/match
                     racket/syntax
                     syntax/parse
                     syntax/datum
                     syntax/id-table
                     syntax/transformer)
         racket/list
         racket/match)
(provide define-interface
         interface?
         unimplemented?
         make-method
         compound-bundle
         make-bundle
         bundle
         bundles->properties)

(module util racket/base
  (require racket/match racket/list)
  (provide (all-defined-out))

  ;; closure : (Listof X) (Listof Y) (X -> (Listof X))
  ;;        -> (values (Listof X) (Hasheq X (Listof Y)))
  ;; Given initial xs and corresponding ys, returns xs closed under get-next,
  ;; along with mapping of x to originating y.
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
    (loop (map cons xs ys) (hasheq) null null)))

(require (submod "." util)
         (for-syntax (submod "." util)))


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

;; create-rtif : Symbol Symbol (Listof Symbol) (Listof Symbol) DeriveProps VarHash
;;            -> RtInterface
(define (create-rtif iname uid supers vnames pubnames derives fallbacks)
  (define len (length vnames))
  (define (vprop-guard in-val st-info)
    (define super-stype (list-ref st-info 6))
    (define vh (in-val super-stype))
    (apply vector-immutable
           vh
           (for/list ([vname (in-list vnames)])
             (hash-ref vh vname))))
  (define-values (vprop vprop? vprop-ref)
    (make-struct-type-property iname vprop-guard derives))
  (define fallbacks*
    (for/fold ([vh (hasheq)]) ([vname (in-list vnames)])
      (hash-set vh vname (hash-ref fallbacks vname (lambda () (unimplemented iname vname))))))
  (for ([key (in-hash-keys fallbacks)] #:when (not (hash-has-key? fallbacks* key)))
    (error 'interface "unexpected key in fallbacks\n  key: ~e\n  interface: ~e"
           key iname))
  (rtif iname uid supers vnames pubnames fallbacks* vprop vprop? vprop-ref))

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
    [(_ ifc:interface-ref pubnames:expr fallbacks:expr derives:expr)
     (define ct (datum ifc.value))
     (match-define (ctif iname uid _ supers vnames) (datum ifc.value))
     (with-syntax ([iname iname] [uid uid] [vnames vnames])
       (with-syntax ([(super-ifcvar ...) (map ctif-rt supers)])
         #`(create-rtif (quote iname) (quote uid) (list super-ifcvar ...)
                        (quote vnames) pubnames derives fallbacks)))]))

(define-syntax (define-interface stx)
  (define-syntax-class var-decl
    #:attributes (make-ast)
    (pattern name:id
             #:attr make-ast (lambda (all-public?) (list #'name all-public?)))
    (pattern [name:id #:dynamic-public]
             #:attr make-ast (lambda (all-public?) (list #'name #t))))
  (define-splicing-syntax-class maybe-super
    (pattern (~seq #:super (super:interface-ref ...)))
    (pattern (~seq) #:with (super ...) null))
  (define-splicing-syntax-class derive-clause
    (pattern (~seq #:derive-property prop:expr prop-value:expr)))
  (syntax-parse stx
    [(_ iname:id s:maybe-super
        (d:var-decl ...)
        (~alt
         (~optional (~seq #:dymamic-public (~bind [all-public? #t]))
                    #:name "dynamic-public clause")
         (~optional (~seq #:fallbacks fallbacks:expr)
                    #:name "fallbacks clause")
         (~optional (~seq #:generics-prefix gprefix:id)
                    #:name "generics prefix clause")
         dc:derive-clause)
        ...)
     (define decl-asts
       (for/list ([make-ast (in-list (datum (d.make-ast ...)))])
         (make-ast (datum all-public?))))
     (define/with-syntax (vname ...) (map car decl-asts))
     (define/with-syntax (pubname ...) (map car (filter cadr decl-asts)))
     (define/with-syntax (gname ...)
       (cond [(datum gprefix)
              (for/list ([vname (in-list (datum (vname ...)))])
                (format-id vname "~a~a" #'gprefix vname))]
             [else #'(vname ...)]))
     (define/with-syntax (rtname rtvlname) (generate-temporaries #'(iname iname)))
     #'(begin
         (define-syntax iname
           (create-ctif (quote-syntax (iname rtname (s.super ...) (vname ...)))))
         (define rtname
           (create-rtif-from-ctif iname (quote (pubname ...)) (~? fallbacks (hasheq))
                                  (list (cons dc.prop (lambda (v) dc.prop-value)) ...)))
         (define gname (make-method* rtname (quote vname) (quote gname) #t)) ...)]))

;; ============================================================
;; Methods

;; make-method : RtInterface Symbol -> (Instance Any ... -> Any)
(define (make-method ifc name)
  (or (make-method* ifc name name #f)
      (error/no-method 'make-method ifc name)))

;; make-method* : RtInterface Symbol Boolean
;;            -> (Instance Any ... -> Any) or #f
(define (make-method* ifc seek-name name allow-private?)
  (let loop ([ifc ifc])
    (or (for/or ([vname (in-list (rtif-vnames ifc))]
                 [index (in-naturals 1)]
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
          (make-keyword-procedure
           (lambda (kws kwargs obj . args)
             (keyword-apply (get-method obj) kws kwargs obj args))
           (procedure-rename
            (lambda (obj . args)
              (apply (get-method obj) obj args))
            name)))
        (ormap loop (rtif-supers ifc)))))

(define (error/no-method who ifc name)
  (error who
         (string-append "no dynamic-public method found"
                        "\n  interface: ~e\n  method name: ~e")
         ifc name))


;; ============================================================
;; Bundles

;; Linkage = (Hash InterfaceKey (Box VarHash))
;; LinkageKey = (cons InterfaceKey Tag)
;; Tag = (Listof Symbol)

;; TaggedInterface = (cons RtInterface Tag)

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

;; Bundle = Bundle1 | (compound-bundle (Listof BundlePart))
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

;; ----------------------------------------

;; make-bundle : #:{export,import} (Listof TaggedInterface) (Lookup -> NameHash)
;;            -> Bundle
;; where Lookup = (TaggedInterface Symbol -> Any)
(define (make-bundle make-table
                     #:export [exports0 null]
                     #:import [imports0 null]
                     #:link [linked-bs null])
  (define exports (tagged-interfaces-closure exports0))
  (define imports (tagged-interfaces-closure imports0))
  (define (init! linkage)
    (define lookup* ;; mutated
      (make-linkage-lookup linkage))
    (define (lookup ifc seek-name)
      (lookup* ifc seek-name))
    (define nh (make-table lookup))
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

;; ----------------------------------------

(begin-for-syntax
  (struct impexp (ostx ifc tag prefix super-prefix))

  (define-syntax-class export-spec
    #:attributes (ast)
    (pattern ifc:interface-ref
             #:attr ast
             (let ([prefix (format-id #'ifc "")]
                   [super-prefix (format-id #'ifc "super-")])
               (impexp this-syntax (datum ifc.value) '() prefix super-prefix)))
    (pattern [ifc:interface-ref
              (~optional (~seq #:tag (tagpart:id ...)))
              (~optional (~seq #:prefix prefix:id))]
             #:attr ast
             (let* ([tag (syntax->datum #'(~? (tagpart ...) ()))]
                    [prefix (or (datum prefix) (format-id #'ifc ""))]
                    [super-prefix (format-id prefix "super-~a" prefix)])
               (impexp this-syntax (datum ifc.value) tag prefix super-prefix))))

  (define-syntax-class import-spec
    #:attributes (ast)
    (pattern ifc:interface-ref
             #:attr ast
             (let ([prefix (format-id #'ifc "")])
               (impexp this-syntax (datum ifc.value) '() prefix #f)))
    (pattern [ifc:interface-ref
              (~optional (~seq #:tag (tagpart:id ...)))
              (~optional (~seq #:prefix prefix:id))]
             #:attr ast
             (let ([tag (syntax->datum #'(~? (tagpart ...) ()))]
                   [prefix (or (datum prefix) (format-id #'ifc ""))])
               (impexp this-syntax (datum ifc.value) tag prefix #f))))

  (define (impexp=? ie1 ie2)
    (match-define (impexp _ ifc1 tag1 prefix1 sprefix1) ie1)
    (match-define (impexp _ ifc2 tag2 prefix2 sprefix2) ie2)
    (and (eq? ifc1 ifc2) (equal? tag1 tag2)
         (bound-identifier=? prefix1 prefix2)
         (or (eq? sprefix1 sprefix2)
             (and sprefix1 sprefix2 (bound-identifier=? sprefix1 sprefix2)))))

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

  (struct bctx (tis vnamess localname=>vname vname=>ref [localname=>t #:mutable]))

  (define (make-bctx einfo-stx)
    (define/with-syntax ((ti-expr eprefix (evname ...)) ...) einfo-stx)
    (define localname=>vname (make-bound-id-table))
    (for ([eprefix (in-list (datum (eprefix ...)))]
          [evnames (in-list (datum ((evname ...) ...)))]
          #:when #t
          [evname (in-list evnames)])
      (define localname (format-id eprefix "~a~a" eprefix evname))
      (bound-id-table-set! localname=>vname localname (syntax-e evname)))
    (define vname=>ref (make-hasheq))
    (bctx (datum (ti-expr ...)) (syntax->datum #'((evname ...) ...))
          localname=>vname vname=>ref #f))

  (define (bctx-add-seen! ctx ids)
    (match-define (bctx _ _ localname=>vname vname=>ref localname=>t) ctx)
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
    [(_ (~optional (~seq #:export (e:export-spec ...)))
        (~optional (~seq #:import (i:import-spec ...)))
        (~optional (~seq #:link link-bs:expr))
        body:expr ...)
     (define eifc+ie-list (check-impexps (datum (~? (e.ast ...) ())) stx "exports"))
     (define iifc+ie-list (check-impexps (datum (~? (i.ast ...) ())) stx "imports"))
     (define/with-syntax ((eti sti eprefix esuperprefix evnames) ...)
       (for/list ([eifc+ie (in-list eifc+ie-list)])
         (match-define (cons ifc (impexp _ _ tag prefix super-prefix)) eifc+ie)
         (list #`(cons #,(ctif-rt ifc) (quote #,tag))
               #`(cons #,(ctif-rt ifc) '(super))
               prefix super-prefix (ctif-vnames ifc))))
     (define/with-syntax ((iti iprefix ivnames) ...)
       (for/list ([iifc+ie (in-list iifc+ie-list)])
         (match-define (cons ifc (impexp _ _ tag prefix _)) iifc+ie)
         (list #`(cons #,(ctif-rt ifc) (quote #,tag))
               prefix (ctif-vnames ifc))))
     #`(make-bundle*
        (bundle1
         (list eti ...) (list iti ...)
         (lambda (linkage)
           (define-names #:strict esuperprefix evnames sti linkage) ...
           (define-names #:lazy iprefix ivnames iti linkage) ...
           (let ()
             (define-syntaxes (the-bctx)
               (make-bctx (quote-syntax ((eti eprefix evnames) ...))))
             (bundle-body-wrap the-bctx body) ...
             (#%expression
              (bundle-body-result the-bctx linkage)))))
        (~? link-bs null))]))

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
       [(define-syntaxes ~! _) ee]
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
     (match-define (bctx etis evnamess _ vname=>ref _) ctx)
     #`(begin
         #,@(for/list ([eti (in-list etis)]
                       [evnames (in-list evnamess)])
              (define/with-syntax lkey-expr
                #`(tagged-interface->linkage-key #,eti))
              (define/with-syntax ((key val) ...)
                (for/list ([evname (in-list evnames)]
                           #:when (hash-has-key? vname=>ref evname))
                  (list #`(quote #,evname)
                        (syntax-local-introduce (hash-ref vname=>ref evname)))))
              #'(let* ([lkey lkey-expr]
                       [super-lkey (cons (car lkey) '(super))]
                       [vhbox (hash-ref linkage lkey)]
                       [super-vh (unbox (hash-ref linkage super-lkey))])
                  (set-box! vhbox (hash-set* super-vh (~@ key val) ...))))
         (void))]))

(define-syntax (define-names stx)
  (syntax-parse stx
    [(_ mode prefix:id (vname:id ...) ti:expr linkage:expr)
     (define/with-syntax (varvar ...)
       (generate-temporaries #'(vname ...)))
     (define/with-syntax (prefixedname ...)
       (for/list ([name (in-list (datum (vname ...)))])
         (format-id #'prefix "~a~a" #'prefix name)))
     (case (syntax->datum #'mode)
       [(#:strict)
        #`(begin
            (define vh (let ([lkey (tagged-interface->linkage-key ti)])
                         (unbox (hash-ref linkage lkey))))
            (begin (define varvar (hash-ref vh (quote vname)))
                   (define-syntax prefixedname
                     (make-variable-like-transformer
                      (quote-syntax varvar))))
            ...)]
       [(#:lazy)
        #`(begin
            (define vhbox (let ([lkey (tagged-interface->linkage-key ti)])
                            (hash-ref linkage lkey)))
            (define (init! who) ;; mutated
              (vh-init! who vhbox '(vname ...) (list varvar ...)))
            (begin (define varvar (box #f))
                   (define-syntax prefixedname
                     (make-variable-like-transformer
                      #'(begin (when init! (init! 'prefixedname)) (unbox varvar)))))
            ...)])]))

(define (vh-init! who vhbox vnames varboxes)
  (unless (unbox vhbox)
    (error who "not initialized"))
  (define vh (unbox vhbox))
  (for ([vname (in-list vnames)] [varbox (in-list varboxes)])
    (set-box! varbox (hash-ref vh vname))))


;; ============================================================
;; Linking Bundles

;; invoke-bundles : Bundle ... -> Void
(define (invoke-bundles #:bind binds0 . bs0)
  (define binds (tagged-interfaces-closure binds0))
  ;; FIXME: check for var collisions
  (define bs (flatten-bundles bs0))
  (define-values (exports linkage initialize-supers!)
    (bundles-prepare-linkage bs))
  (for ([bind (in-list binds)])
    (define lkey (tagged-interface->linkage-key bind))
    (unless (hash-has-key? linkage lkey)
      (error 'invoke-bundles "~a\n  tagged interface: ~e"
             "tagged interface not exported" bind)))
  (initialize-supers! #f)
  (run-bundles bs linkage)
  (for/fold ([h (hasheq)]) ([bind (in-list binds)])
    (define lkey (tagged-interface->linkage-key bind))
    (define bindvh (unbox (hash-ref linkage lkey)))
    (define vnames (rtif-vnames (car bind)))
    (for/fold ([h h]) ([vname (in-list vnames)])
      (hash-set h vname (hash-ref bindvh vname)))))

;; bundles-prepare-linkage : (Listof Bundle1)
;;                        -> (values (Listof TaggedInterface)
;;                                   Linkage
;;                                   (StructType/#f -> Void))
(define (bundles-prepare-linkage bs)
  (define exports (tagged-interfaces-closure (append* (map bundle1-exports bs))))
  (define exported-ifcs (remove-duplicates (map car exports)))
  (define supers-linkage
    (for/fold ([linkage (hash)]) ([ifc (in-list exported-ifcs)])
      (define linkage-key (cons (rtif-uid ifc) '(super)))
      (hash-set linkage linkage-key (box #f))))
  (define linkage (check-bundles bs supers-linkage))
  (define (initialize-supers! stype)
    (for ([ifc (in-list exported-ifcs)])
      (define super-vh (rtif-get-stype-vh ifc stype))
      (define linkage-key (cons (rtif-uid ifc) '(super)))
      (set-box! (hash-ref linkage linkage-key) super-vh)))
  (values exports linkage initialize-supers!))

;; check-bundles : (Listof BundlePart1) Linkage -> Linkage
(define (check-bundles bs base-linkage)
  (define linkage (build-linkage bs base-linkage))
  (check-linkage bs linkage)
  (for ([b (in-hash-values linkage)]) (set-box! b #f))
  linkage)

;; build-linkage : (Listof BundlePart1) Linkage -> Linkage
;; PRE: base-linkage boxes are empty
(define (build-linkage bs base-linkage)
  ;; handle-bundle : Bundle1 Linkage -> Linkage
  (define (handle-bundle b linkage)
    (foldl handle-export linkage (bundle1-exports b)))
  ;; handle-export : TaggedInterface Linkage -> Linkage
  (define (handle-export export linkage)
    (define lkey (tagged-interface->linkage-key export))
    (cond [(hash-ref linkage lkey #f)
           => (lambda (link-box)
                (error 'check-bundles "duplicate export: ~e" (unbox link-box)))]
          [else (hash-set linkage lkey (box export))]))
  (foldl handle-bundle base-linkage bs))

;; check-linkage : (Listof BundlePart1) Linkage -> Void
(define (check-linkage bs linkage)
  ;; check-bundle : Bundle1 -> Void
  (define (check-bundle b)
    (for-each check-import (bundle1-imports b)))
  ;; check-import : TaggedInterface -> Void
  (define (check-import import)
    (define key (tagged-interface->linkage-key import))
    (unless (hash-has-key? linkage key)
      (error 'check-bundles "import missing matching export\n  import: ~e" import)))
  (for-each check-bundle bs))

;; run-bundles : (Listof Bundle1) Linkage -> Void
(define (run-bundles bs linkage)
  (for ([b (in-list bs)])
    ((bundle1-init! b) linkage)))

;; ----------------------------------------

;; bundles->properties : Bundle1 ...
;;                    -> (Listof (cons VarProp (StructType -> VarHash)))
(define (bundles->properties . bs0)
  (define bs (flatten-bundles bs0))
  (define-values (exports linkage initialize-supers!)
    (bundles-prepare-linkage bs))
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
