;; Copyright 2012-2018 Ryan Culpepper
;; Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
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
         racket/match
         racket/contract/base
         racket/random
         racket/string
         "interfaces.rkt"
         "error.rkt")
(provide impl-base%
         info-impl-base%
         ctx-base%
         state-mixin
         state-ctx%
         process-input
         to-impl
         to-info
         to-spec
         shrink-bytes
         make-sized-copy
         ceil/
         config/c
         check-config
         config-ref
         check/ref-config
         version->list
         version->string
         version>=?
         crypto-random-bytes)

;; Convention: methods starting with `-` (eg, `-digest-buffer`) are
;; hooks for overrriding. They receive pre-checked arguments, and they
;; are called within the appropriate mutex and state, if applicable.

;; ============================================================

(define impl-base%
  (class* object% (impl<%>)
    (init-field spec factory)
    (define/public (about) (format "~a ~a" (send (get-factory) get-name) (get-spec)))
    (define/public (to-write-string prefix)
      (format "~a~a:~s" (or prefix "impl:") (send (get-factory) get-name) (get-spec)))
    (define/public (get-info) #f)
    (define/public (get-spec) spec)
    (define/public (get-factory) factory)
    (super-new)))

(define info-impl-base%
  (class* object% (impl<%>)
    (init-field info factory)
    (define/public (about) (format "~a ~a" (send (get-factory) get-name) (get-spec)))
    (define/public (to-write-string prefix)
      (format "~a~a:~s" (or prefix "impl:") (send (get-factory) get-name) (get-spec)))
    (define/public (get-info) info)
    (define/public (get-spec) (send info get-spec))
    (define/public (get-factory) factory)
    (super-new)))

(define ctx-base%
  (class* object% (ctx<%>)
    (init-field impl)
    (define/public (about) (format "~a context" (send impl about)))
    (define/public (to-write-string prefix) (send impl to-write-string (or prefix "ctx:")))
    (define/public (get-impl) impl)
    (super-new)))

;; ----------------------------------------

(define state-mixin
  (mixin () (state<%>)
    (init-field state)
    (field [sema (make-semaphore 1)])
    (super-new)

    (define/public (with-state #:ok [ok-states #f]
                     #:pre  [pre-state #f]
                     #:post [post-state #f]
                     #:msg  [msg #f]
                     proc)
      (call-with-semaphore sema
        (lambda ()
          (when ok-states (unless (memq state ok-states) (bad-state state ok-states msg)))
          (when pre-state (set-state pre-state))
          (begin0 (proc)
            (when post-state (set-state post-state))))))

    (define/public (set-state new-state)
      (unless (equal? state new-state) (set! state new-state)))

    (define/public (bad-state state ok-states msg)
      (crypto-error "wrong state\n  state: ~a~a" (describe-state state) (or msg "")))
    (define/public (describe-state state)
      (format "~s" state))
    ))

(define state-ctx% (state-mixin ctx-base%))

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

(define (to-impl src0 [fail-ok? #f] #:lookup [lookup #f] #:what [what #f])
  (let loop ([src src0])
    (cond [(is-a? src impl<%>) src]
          [(is-a? src ctx<%>) (loop (send src get-impl))]
          [(and lookup (lookup src)) => values]
          [fail-ok? #f]
          [else (crypto-error "could not get implementation\n  ~a: ~e"
                              (or what "given") src0)])))

(define (to-info src [fail-ok? #f] #:lookup [lookup #f] #:what [what #f])
  ;; assumes impl<%> is also info<%>
  (cond [(to-impl src #t) => values]
        [(and lookup (lookup src)) => values]
        [fail-ok? #f]
        [else (crypto-error "could not get info\n  ~a: ~e" (or what "given") src)]))

(define (to-spec src)
  ;; Assumes src is Spec | Impl | Ctx
  (cond [(to-impl src #t) => (lambda (impl) (send impl get-spec))]
        [else src]))

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

;; A Config is (listof (list Symbol Any))
(define config/c (listof (list/c symbol? any/c)))

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
