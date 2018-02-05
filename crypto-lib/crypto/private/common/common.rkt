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
         racket/string
         racket/random
         "catalog.rkt"
         "interfaces.rkt"
         "error.rkt"
         "factory.rkt"
         "ufp.rkt"
         "../rkt/padding.rkt")
(provide impl-base%
         ctx-base%
         state-mixin
         state-ctx%
         factory-base%
         digest-impl%
         digest-ctx%
         cipher-impl-base%
         multikeylen-cipher-impl%
         cipher-ctx%
         process-input
         get-impl*
         get-spec*
         get-factory*
         shrink-bytes
         keygen-spec/c
         check-keygen-spec
         keygen-spec-ref
         crypto-random-bytes)

;; Convention: methods starting with `-` (eg, `-digest-buffer`) are
;; hooks for overrriding. They receive pre-checked arguments, and they
;; are called within the appropriate mutex and state, if applicable.

;; ============================================================

(define impl-base%
  (class* object% (impl<%>)
    (init-field spec factory)
    (define/public (get-spec) spec)
    (define/public (get-factory) factory)
    (super-new)))

(define ctx-base%
  (class* object% (ctx<%>)
    (init-field impl)
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
      (crypto-error "wrong state\n  state: ~s~a" state (or msg "")))
    ))

(define state-ctx% (state-mixin ctx-base%))

;; ============================================================
;; Factory

(define factory-base%
  (class* object% (factory<%>)
    (super-new)

    (define/public (get-name) #f)

    ;; digest-table : hasheq[DigestSpec => DigestImpl/'none]
    (define digest-table (make-hasheq))
    ;; cipher-table : hash[CipherSpec => CipherImpl/'none]
    (define cipher-table (make-hash))
    ;; pk-table : hasheq[PKSpec => PKImpl/'none]
    (define pk-table (make-hasheq))

    (define/public (get-digest spec)
      (cond [(hash-ref digest-table spec #f)
             => (lambda (impl/none)
                  (and (digest-impl? impl/none) impl/none))]
            [else
             (let ([di (get-digest* spec)])
               (hash-set! digest-table spec (or di 'none))
               di)]))

    (define/public (get-cipher spec)
      (cond [(hash-ref cipher-table spec #f)
             => (lambda (impl/none)
                  (and (cipher-impl? impl/none) impl/none))]
            [else
             (let* ([ci/s (get-cipher* spec)]
                    [ci (cond [(list? ci/s)
                               (and (pair? ci/s)
                                    (andmap cdr ci/s)
                                    (new multikeylen-cipher-impl%
                                         (spec spec)
                                         (factory this)
                                         (impls ci/s)))]
                              [(cipher-impl? ci/s) ci/s]
                              [else #f])])
               (hash-set! cipher-table spec (or ci 'none))
               ci)]))

    (define/public (get-pk spec)
      (cond [(hash-ref pk-table spec #f)
             => (lambda (impl/none)
                  (and (pk-impl? impl/none) impl/none))]
            [else
             (let ([pki (get-pk* spec)])
               (hash-set! pk-table spec (or pki 'none))
               pki)]))

    (define/public (get-pk-reader) #f)  ; -> pk-read-key<%>

    (define/public (get-digest* spec) #f) ;; -> (U #f DigestImpl)
    (define/public (get-cipher* spec) #f) ;; -> (U #f CipherImpl (listof (cons nat CipherImpl)))
    (define/public (get-pk* spec) #f)   ;; -> (U #f DigestIpl

    (define/public (get-kdf spec) #f)
    ))

;; ============================================================
;; Digest

(define digest-impl%
  (class* impl-base% (digest-impl<%>)
    (super-new)
    (inherit get-spec)

    (define/public (get-size) (digest-spec-size (get-spec)))
    (define/public (get-block-size) (digest-spec-block-size (get-spec)))

    (define/public (sanity-check #:size [size #f] #:block-size [block-size #f])
      ;; Use digest-spec-{block-,}size directly so that subclasses can
      ;; override get-size and get-block-size with faster versions.
      (when size
        (unless (= size (digest-spec-size (get-spec)))
          (crypto-error "internal error in digest ~v size: expected ~s but got ~s"
                        (get-spec) (digest-spec-size (get-spec)) size)))
      (when block-size
        (unless (= block-size (digest-spec-block-size (get-spec)))
          (crypto-error "internal error in digest ~v block size: expected ~s but got ~s"
                        (get-spec) (digest-spec-block-size (get-spec)) block-size))))

    (abstract new-ctx)        ;; -> digest-ctx<%>
    (abstract new-hmac-ctx)   ;; Bytes -> digest-ctx<%>

    (define/public (digest src)
      (define (fallback) (send (new-ctx) digest src))
      (match src
        [(? bytes?) (or (-digest-buffer src 0 (bytes-length src)) (fallback))]
        [(bytes-range buf start end) (or (-digest-buffer buf start end) (fallback))]
        [_ (fallback)]))

    (define/public (hmac key src)
      (define (fallback) (send (new-hmac-ctx key) digest src))
      (match src
        [(? bytes?) (or (-hmac-buffer key src 0 (bytes-length src)) (fallback))]
        [(bytes-range buf start end) (or (-hmac-buffer key buf start end) (fallback))]
        [_ (fallback)]))

    ;; {-digest,-hmac}-buffer : ... -> Bytes/#f
    ;; Return bytes if can compute digest/hmac directly, #f to fall back
    ;; to default ctx code.
    (define/public (-digest-buffer src src-start src-end) #f)
    (define/public (-hmac-buffer key src src-start src-end) #f)
    ))

(define digest-ctx%
  (class* (state-mixin ctx-base%) (digest-ctx<%>)
    (super-new [state 'open])
    (inherit get-impl with-state)
    (define/public (get-size) (send (get-impl) get-size))

    (define/public (digest src)
      (update src)
      (final))

    (define/public (update src)
      (with-state #:ok '(open)
        (lambda () (process-input src (lambda (buf start end) (-update buf start end))))))

    (define/public (final)
      (with-state #:ok '(open) #:post 'closed
        (lambda ()
          (define dest (make-bytes (get-size)))
          (-final! dest)
          dest)))

    (define/public (copy)
      (with-state #:ok '(open) (lambda () (-copy))))

    (abstract -update) ;; Bytes Nat Nat -> Void
    (abstract -final!) ;; Bytes -> Void
    (define/public (-copy) #f) ;; -> digest-ctx<%> or #f
    ))

;; ============================================================
;; Cipher

(define cipher-impl-base%
  (class* impl-base% (cipher-impl<%>)
    (inherit-field spec)
    (super-new)

    ;; cache block-size; used often to calculate space needed
    (define block-size (cipher-spec-block-size spec))
    (define/public (get-block-size) block-size)

    (define/public (aead?) (cipher-spec-aead? spec))
    (define/public (get-iv-size) (cipher-spec-iv-size spec))
    (define/public (get-default-key-size) (cipher-spec-default-key-size spec))
    (define/public (get-key-sizes) (cipher-spec-key-sizes spec))
    (define/public (get-auth-size) (cipher-spec-default-auth-size spec))

    (abstract get-chunk-size)
    (abstract new-ctx)
    ))

(define multikeylen-cipher-impl%
  (class* impl-base% (cipher-impl<%>)
    (init-field impls) ;; (nonempty-listof (cons nat cipher-impl%))
    (inherit-field spec)
    (super-new)

    (define/public (get-default-key-size) (caar impls))
    (define/public (get-key-sizes) (map car impls))

    (define/private (rep) (cdar impls)) ;; representative impl
    (define/public (aead?) (send (rep) aead?))
    (define/public (get-block-size) (send (rep) get-block-size))
    (define/public (get-iv-size) (send (rep) get-iv-size))
    (define/public (get-auth-size) (send (rep) get-auth-size))
    (define/public (get-chunk-size) (send (rep) get-chunk-size))

    (define/public (new-ctx key . args)
      (cond [(assoc (bytes-length key) impls)
             => (lambda (keylen+impl)
                  (send/apply (cdr keylen+impl) new-ctx key args))]
            [else
             (check-key-size spec (bytes-length key))
             (error 'multikeylen-cipher-impl%
                    (string-append "internal error: no implementation for key length"
                                   "\n  cipher: ~e\n  given: ~s bytes\n  available: ~a")
                    spec (bytes-length key)
                    (string-join (map number->string (map car impls)) ", "))]))
    ))

;; ----------------------------------------

;; cipher-ctx%
;; - enforces update-aad -> update -> final state machine
;; - accepts data from varied input in varied sizes, passes to underlying
;;   crypt routines in multiples of chunk-size (except last call)
;; - handles PKCS7 padding
;; - handles attached authentication tags

(define cipher-ctx%
  (class* state-ctx% (cipher-ctx<%>)
    (init-field encrypt? pad? auth-len attached-tag?)
    ;; auth-len : Nat -- 0 means no tag
    (inherit-field impl state)
    (field [auth-tag-out #f]
           [out (open-output-bytes)])
    (inherit with-state set-state)
    (super-new [state 1])

    (set-state (if (send impl aead?) 1 2))

    ;; State is Nat
    ;; 1 - ready for AAD
    ;; 2 - AAD done, ready for {plain,cipher}text
    ;; 3 - closed (but can read auth tag)
    (define/override (bad-state state ok-states msg)
      (crypto-error "wrong state\n  state: ~a~a"
                    (case state
                      [(1) "ready for AAD or input"]
                      [(2) "ready for input"]
                      [(3) "closed"])
                    msg))

    (define/public (get-encrypt?) encrypt?)
    (define/public (get-block-size) (send impl get-block-size))
    (define/public (get-chunk-size) (send impl get-chunk-size))
    (define/public (get-output) (get-output-bytes out #t))

    (define/public (update-aad src)
      (unless (null? src)
        (with-state #:ok '(1) #:pre 1
          (lambda ()
            (process-input src (lambda (buf start end) (-update-aad buf start end)))))))

    (define/public (update src)
      (with-state #:ok '(1 2) #:post 2
        (lambda ()
          (when (member state '(1)) (-finish-aad))
          (set-state 3)
          (process-input src (lambda (buf start end) (-update buf start end))))))

    (define/public (final tag)
      (cond [encrypt?
             (when tag
               (crypto-error "cannot set authentication tag for encryption context"))]
            [attached-tag? ;; decrypt w/ attached tag
             (when tag
               (crypto-error "cannot set authentication tag for decryption context with attached tag"))]
            [else ;; decrypt w/ detached tag
             (let ([tag (or tag #"")])
               (unless (= (bytes-length tag) auth-len)
                 (crypto-error "wrong size for authentication tag\n  expected: ~s\n  given: ~s"
                               auth-len (bytes-length tag))))])
      (with-state #:ok '(1 2) #:post 3
        (lambda ()
          (when (member state '(1)) (-finish-aad))
          (set-state 3)
          (begin0 (-final (if encrypt? #f (or tag #"")))
            (-close)))))

    (define/public (get-auth-tag)
      (cond [encrypt?
             ;; -final sets auth-tag-out for encryption context
             ;; #"" for non-AEAD cipher
             (with-state #:ok '(3)
               (lambda () auth-tag-out))]
            [else ;; decrypt
             (crypto-error "cannot get authentication tag for decryption context")]))

    ;; ----------------------------------------

    ;; -update-aad : Bytes Nat Nat -> Void
    (define/public (-update-aad buf start end)
      (send aad-ufp update buf start end))

    ;; -finish-aad : -> Void
    (define/public (-finish-aad)
      (send aad-ufp finish 'ignored))

    ;; -update : Bytes Nat Nat -> Void
    (define/public (-update buf start end)
      (send crypt-ufp update buf start end))

    ;; -final : #f/Bytes -> Void
    (define/public (-final tag)
      (send crypt-ufp finish tag))

    ;; -close : -> Void
    (define/public (-close) (void))

    ;; -make-crypt-sink : -> UFP[#f/AuthTag => ]
    (define/public (-make-crypt-sink)
      (sink-ufp (lambda (buf start end) (write-bytes buf out start end))
                (lambda (result) (set! auth-tag-out result))))

    ;; -make-aad-sink : -> UFP[#f => ]
    (define (-make-aad-sink)
      (define (update inbuf instart inend) (-do-aad inbuf instart inend))
      (define (finish _ignored) (void))
      (sink-ufp update finish))

    (abstract -do-aad) ;; Bytes Nat Nat -> Void

    ;; -make-crypt-ufp : Boolean UFP -> UFP[Bytes,#f/AuthTag => AuthTag/#f]
    (define/private (-make-crypt-ufp enc? next)
      (define (update inbuf instart inend)
        ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
        (define outlen0 (+ (- inend instart) (get-block-size)))
        (define outbuf (make-bytes outlen0))
        (define outlen (-do-crypt enc? #f inbuf instart inend outbuf))
        (unless (= outlen (- inend instart))
          (crypto-error "internal error, outlen = ~s, inlen = ~s" outlen (- inend instart)))
        (send next update outbuf 0 outlen))
      (define (finish partial auth-tag)
        ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
        (define outlen0 (* 2 (get-chunk-size)))
        (define outbuf (make-bytes outlen0))
        (define outlen (-do-crypt enc? #t partial 0 (bytes-length partial) outbuf))
        (unless (= outlen (bytes-length partial))
          (crypto-error "internal error, outlen = ~s, partial = ~s" outlen (bytes-length partial)))
        (send next update outbuf 0 outlen)
        (cond [enc?
               (send next finish (-do-encrypt-end auth-len))]
              [else
               (unless (= (bytes-length auth-tag) auth-len)
                 (crypto-error "authentication tag wrong size\n  expected: ~s\n  given: ~s"
                               auth-len (bytes-length auth-tag)))
               (-do-decrypt-end auth-tag)
               (send next finish #f)]))
      (sink-ufp update finish))

    (abstract -do-crypt) ;; Enc? Final? Bytes Nat Nat Bytes -> Nat
    (abstract -do-encrypt-end) ;; Nat -> Tag      -- fetch auth tag
    (abstract -do-decrypt-end) ;; Nat Tag -> Void -- check auth tag

    ;; ----------------------------------------
    ;; Initialization

    ;; It's most convenient if we know the auth-length up front. That
    ;; simplifies the creation of the split-right-ufp for decrypting with
    ;; attached tag.

    (define aad-ufp
      ;; update-aad
      ;;   source -> chunk -> add-right -> update-aad
      ;;          #f       buf,#f       #f
      (let* ([ufp (-make-aad-sink)]
             [ufp (add-right-ufp ufp)]
             [ufp (chunk-ufp (get-chunk-size) ufp)])
        ufp))

    (define crypt-ufp
      (cond [encrypt?
             ;; encrypt (detached tag) =
             ;;   source -> chunk -> pad  -> auth-encrypt -> sink
             ;;          #f       buf,#f  buf,#f          tag
             ;;
             ;; encrypt/attached-tag =
             ;;   source -> chunk -> pad  -> auth-encrypt -> add-right -> push #f -> sink
             ;;          #f       buf,#f  buf,#f          tag          ()         #f
             (let* ([ufp (-make-crypt-sink)]
                    [ufp (if attached-tag? (add-right-ufp (push-ufp #f ufp)) ufp)]
                    [ufp (-make-crypt-ufp #t ufp)]
                    [ufp (if pad? (pad-ufp (get-block-size) ufp) ufp)]
                    [ufp (chunk-ufp (get-chunk-size) ufp)])
               ufp)]
            [else ;; decrypt
             ;; decrypt (detached tag) =
             ;;   source -> chunk -> auth-decrypt -> split-right -> unpad -> add-right -> sink
             ;;          tag      buf,tag         #f             buf,#f   buf,#f       #f
             ;;
             ;; decrypt/attached-tag = 
             ;;   source -> pop -> split-right -> chunk -> pad  -> auth-decrypt -> (...see above)
             ;;          #""    ()             tag      buf,tag buf,tag         #f
             (let* ([ufp (-make-crypt-sink)]
                    [ufp (cond [pad?
                                (let* ([ufp (add-right-ufp ufp)]
                                       [ufp (unpad-ufp ufp)]
                                       [ufp (split-right-ufp (get-block-size) ufp)])
                                  ufp)]
                               [else ufp])]
                    [ufp (-make-crypt-ufp #f ufp)]
                    [ufp (chunk-ufp (get-chunk-size) ufp)]
                    ;; FIXME: need to delay until we have auth-len ...
                    [ufp (if (and attached-tag? (positive? auth-len))
                             (pop-ufp (split-right-ufp auth-len ufp))
                             ufp)])
               ufp)]))
    ))

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

(define (get-impl* src0 [fail-ok? #f])
  (let loop ([src src0])
    (cond [(is-a? src impl<%>)
           src]
          [(is-a? src ctx<%>)
           (loop (send src get-impl))]
          [fail-ok?
           #f]
          [else
           (crypto-error "internal error: cannot get impl\n  from: ~e" src0)])))

(define (get-spec* src [fail-ok? #f])
  (cond [(or (symbol? src) (list? src))
         src]
        [(get-impl* src #t)
         => (lambda (i) (send i get-spec))]
        [fail-ok?
         #f]
        [else
         (crypto-error "internal error: cannot get spec\n  from: ~e" src)]))

(define (get-factory* src [fail-ok? #f])
  (cond [(is-a? src factory<%>)
         src]
        [(get-impl* src #t)
         => (lambda (i) (send i get-factory))]
        [fail-ok?
         #f]
        [else
         (crypto-error "internal error: cannot get factory\n  from: ~e" src)]))

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))

(define keygen-spec/c
  (listof (list/c symbol? any/c)))

(define (check-keygen-spec spec allowed)
  ;; Assume already checked keygen-spec/c
  ;; Check entries
  (for ([entry (in-list spec)])
    (cond [(assq (car entry) allowed)
           => (lambda (allowed-entry)
                (unless ((cadr allowed-entry) (cadr entry))
                  (crypto-error "bad key-generation option value\n  key: ~e\n  expected: ~a\n  got: ~e"
                                (car entry)
                                (caddr allowed-entry)
                                (cadr entry))))]
          [else
           (crypto-error "bad key-generation option\n  key: ~e\n  value: ~e"
                         (car entry) (cadr entry))]))
  ;; FIXME: check duplicates?
  (void))

(define (keygen-spec-ref spec key)
  (cond [(assq key spec) => cadr]
        [else #f]))
