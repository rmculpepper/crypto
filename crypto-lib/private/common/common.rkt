;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/contract/base
         racket/random
         racket/string
         scramble/bundle
         scramble/struct
         "catalog.rkt"
         "interfaces.rkt"
         "error.rkt")
(provide (struct-out info-impl-base)
         (interface-out state$)
         (struct-out state-ctx)
         process-input
         shrink-bytes
         make-sized-copy
         ceil/
         config/c
         check-config
         config-ref
         check/ref-config
         check-null-config
         version->list
         version->string
         version>=?
         crypto-random-bytes)

;; ============================================================

(struct info-impl-base (info factory)
  #:properties
  (method-properties
   #:export ([info$ #:prefix %]
             [impl$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs info-impl-base)
   ;; ----
   (define (%get-spec self) ($get-spec (.info self)))
   ;; ----
   (define (%impl-info self) (.info self))
   (define (%impl-factory self) (.factory self))
   ;; ----
   (define (%to-write-string)
     (format "~s" ($get-spec self)))
   (define (%to-write-prefixes)
     (list ($factory-name (.factory self))))))

;; ----------------------------------------

(define-interface state$
  ([call-with-state (->* [state$? (-> any)]
                         [#:ok list? #:pre any/c #:post any/c #:msg (or/c string? #f)]
                         any)]
   ;; Acquires mutex, checks state, and updates state before and after calling proc.
   [set-state       (-> state$? any/c void?)]
   [describe-state  (-> state$? any/c string?)])
  #:generics-prefix $)

(struct state-ctx ctx
  (sema [state #:mutable])
  #:properties
  (method-properties
   #:export ([state$ #:prefix %])
   (define-struct-abbrevs state-ctx)
   ;; ----
   (define (%call-with-state self proc
                             #:ok   [ok-states #f]
                             #:pre  [pre-state #f]
                             #:post [post-state #f]
                             #:msg  [msg #f])
     (call-with-semaphore (.sema self)
       (lambda ()
         (when ok-states
           (define now-state (.state self))
           (unless (memq now-state ok-states)
             (bad-state self now-state ok-states msg)))
         (when pre-state ($set-state self pre-state))
         (begin0 (proc)
           (when post-state ($set-state self post-state))))))
   (define (%set-state self new-state)
     (unless (equal? (.state self) new-state)
       (.state-set! self new-state)))
   (define (%describe-state self state)
     (format "~s" self state))
   (define (bad-state self state ok-states msg)
     (crypto-error "wrong state\n  state: ~a~a"
                   ($describe-state (.state self))
                   (or msg "")))))

#;
(define-interface clone$
  (clone
   prepare-clone   ;; -> (values (X ... -> Self) (Listof X) (Self -> Void))
   )
  #:fallbacks
  (let ()
    (define (clone self)
      (define-values (maker args patchup) ($prepare-clone self))
      (define copy (apply maker args))
      (patchup copy)
      copy)
    (define (prepare-clone self)
      (define (invalid . args) (error 'clone "invalid constructor"))
      (values invalid null void))
    (hasheq 'clone clone 'prepare-clone prepare-clone))
  #:generics-prefix $)

;; ============================================================
;; Input

;; process-input : Input (Bytes Nat Nat -> Void) -> Void
(define (process-input src process)
  (let loop ([src src])
    (match src
      [(? bytes?) (process src 0 (bytes-length src))]
      [(bytes-range buf start end) (process buf start end)]
      [(? input-port?)
       (process-input-port src process)]
      [(? string?)
       ;; Alternative: could process string in chunks like process-input.
       ;; Note: open-input-bytes makes copy, so can't just use that.
       (loop (string->bytes/utf-8 src))]
      [(? list?) (for ([sub (in-list src)]) (loop sub))])))

;; process-input-port : InputPort (Bytes Nat Nat -> Void) -> Void
(define DEFAULT-CHUNK 1000)
(define (process-input-port in process #:chunk [chunk-size DEFAULT-CHUNK])
  (define buf (make-bytes chunk-size))
  (let loop ()
    (define len (read-bytes! buf in))
    (unless (eof-object? len)
      (process buf 0 len)
      (loop))))

;; ============================================================

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))

;; make-sized-copy : Nat Bytes -> Bytes[size]
;; Returns a fresh copy of buf extended or truncated to size.
(define (make-sized-copy size buf)
  (define copy (make-bytes size))
  (bytes-copy! copy 0 buf 0 (min (bytes-length buf) size))
  copy)

;; ceil/ : Nat PosNat -> Nat
;; Equivalent to (ceiling (/ a b)).
(define (ceil/ a b)
  (quotient (+ a b -1) b))

;; ============================================================

;; A ConfigSpec is (listof ConfigSpecEntry)
;; A ConfigSpecEntry is one of
;; - (list Symbol Predicate String/#f '#:req)     -- required
;; - (list Symbol Predicate String/#f '#:opt Any) -- optional w/ default
;; - (list Symbol Predicate String/#f '#:alt Symbol) -- requires this or alt but not both

(define (check-config config0 spec what)
  ;; Assume already checked config/c, now check entries
  (define config config0)
  (for ([entry (in-list config)])
    (match-define (list key value) entry)
    (cond [(assq key spec)
           => (match-lambda
                [(list* _ pred? expected _)
                 (unless (pred? value)
                   (crypto-error "bad option value for ~a\n  option: ~e\n  expected: ~a\n  given: ~e"
                                 what key (or expected (object-name pred?)) value))])]
          [else
           (crypto-error "unsupported option for ~a\n  option: ~e\n  value: ~e"
                         what key value)]))
  (for/fold ([config config]) ([aentry (in-list spec)])
    (match aentry
      [(list key _ _ '#:req)
       (unless (assq key config)
         (crypto-error "missing required option for ~a\n  option: ~e\n  given: ~e"
                       what key config0))
       config]
      [(list key _ _ '#:opt default)
       (if (assq key config)
           config
           (cons (list key default) config))]
      [(list key _ _ '#:alt key2)
       (if (assq key config)
           (when (assq key2 config)
             (crypto-error "conflicting options for ~a\n  options: ~e and ~e\n  given: ~e"
                           what key key2 config0))
           (unless (assq key2 config)
             (crypto-error "missing required option for ~a\n  option: either ~e or ~e\n  given: ~e"
                           what key key2 config0)))
       config])))

(define (config-ref config key [default #f])
  (cond [(assq key config) => (lambda (e) (or (cadr e) default))]
        [else default]))

(define (check/ref-config keys config spec what)
  (define config* (check-config config spec what))
  (apply values (for/list ([key (in-list keys)]) (config-ref config* key))))

(define (check-null-config config what #:in [impl #f])
  (unless (null? config)
    (define impl-note (if impl ";\n implementation limitation" ""))
    (crypto-error "no options supported for ~a~a\n  given: ~e"
                  what impl-note config #:in impl)))

;; ----------------------------------------

;; version->list : String/#f -> (Listof Nat)/#f
(define (version->list str)
  (cond [(eq? str #f) #f]
        [(regexp-match #rx"^([0-9]+(?:[.][0-9]+)*)" str)
         => (match-lambda
              [(list _ s) (map string->number (string-split s #rx"[.]"))])]
        [else (internal-error "invalid version string: ~e" str)]))

;; version->string : (Listof Nat)/#f -> String/#f
(define (version->string v)
  (and v (string-join (map number->string v) ".")))

;; version>=? : (Listof Nat)/#f (Listof Nat) -> Boolean
(define (version>=? v1 v2)
  (match* [v1 v2]
    [[#f _] #f]
    [[(cons p1 v1*) (cons p2 v2*)]
     (or (> p1 p2)
         (and (= p1 p2) (version>=? v1* v2*)))]
    [[(cons p1 v1*) '()] #t]
    ;; FIXME: currently 1.0 < 1.0.0; maybe consider equal?
    [['() (cons p2 v2*)] #f]))
