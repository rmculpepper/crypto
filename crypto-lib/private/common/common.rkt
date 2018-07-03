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
         racket/list
         racket/match
         racket/contract/base
         racket/random
         racket/string
         "catalog.rkt"
         "interfaces.rkt"
         "error.rkt"
         "factory.rkt"
         "ufp.rkt"
         "util.rkt"
         (prefix-in pw: "../rkt/pwhash.rkt"))
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
         kdf-impl-base%
         kdf-pwhash-argon2
         kdf-pwhash-scrypt
         kdf-pwhash-pbkdf2
         kdf-pwhash-verify
         process-input
         to-impl
         to-info
         to-spec
         shrink-bytes
         make-sized-copy
         config/c
         check-config
         config-ref
         check/ref-config
         config:pbkdf2-base
         config:pbkdf2-kdf
         config:scrypt-pwhash
         config:scrypt-kdf
         config:argon2-base
         config:argon2-kdf
         config:rsa-keygen
         config:dsa-paramgen
         config:dh-paramgen
         config:ec-paramgen
         config:eddsa-keygen
         config:ecx-keygen
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
    (define/public (get-info) #f)
    (define/public (get-spec) spec)
    (define/public (get-factory) factory)
    (super-new)))

(define info-impl-base%
  (class* object% (impl<%>)
    (init-field info factory)
    (define/public (about) (format "~a ~a" (send (get-factory) get-name) (get-spec)))
    (define/public (get-info) info)
    (define/public (get-spec) (send info get-spec))
    (define/public (get-factory) factory)
    (super-new)))

(define ctx-base%
  (class* object% (ctx<%>)
    (init-field impl)
    (define/public (about) (format "~a context" (send impl about)))
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
    (init-field [ok? #t])
    (super-new)

    (define/public (get-name) #f)
    (define/public (get-version) (and ok? '()))

    (define/public (info key)
      (case key
        [(version) (and ok? (get-version))]
        [(all-digests) (filter (lambda (s) (get-digest s)) (list-known-digests))]
        [(all-ciphers) (filter (lambda (x) (get-cipher x)) (list-known-ciphers))]
        [(all-pks)     (filter (lambda (x) (get-pk x))     (list-known-pks))]
        [(all-ec-curves)    '()]
        [(all-eddsa-curves) '()]
        [(all-ecx-curves)   '()]
        [(all-kdfs)    (filter (lambda (k) (get-kdf k))    (list-known-kdfs))]
        [else #f]))

    (define/public (print-info)
      (void))

    (define/public (print-avail)
      (define (pad-to v len)
        (let ([vs (format "~a" v)])
          (string-append vs (make-string (- len (string-length vs)) #\space))))
      ;; == Digests ==
      (let ([all-digests (info 'all-digests)])
        (when (pair? all-digests)
          (printf "Available digests:\n")
          (for ([di (in-list (info 'all-digests))])  (printf " ~v\n" di))))
      ;; == Ciphers ==
      (let ([all-ciphers (info 'all-ciphers)])
        (when (pair? all-ciphers)
          (printf "Available ciphers:\n")
          (define cipher-groups (group-by car all-ciphers))
          (define cipher-max-len
            (apply max 0 (for/list ([cg (in-list cipher-groups)] #:when (> (length cg) 1))
                           (string-length (symbol->string (caar cg))))))
          (for ([group (in-list cipher-groups)])
            (cond [(> (length group) 1)
                   (printf " `(~a ,mode)  for mode in ~a\n"
                           (pad-to (car (car group)) cipher-max-len)
                           (map cadr group))]
                  [else (printf " ~v\n" (car group))]))))
      ;; == PK ==
      (let ([all-pks (info 'all-pks)])
        (when (pair? all-pks)
          (printf "Available PKs:\n")
          (for ([pk (in-list all-pks)]) (printf " ~v\n" pk))))
      ;; == EC named curves ==
      (let ([all-curves (info 'all-ec-curves)])
        (define all-curve-vs (for/list ([c (in-list all-curves)]) (format "~v" c)))
        (when (pair? all-curves)
          (printf "Available 'ec named curves:\n")
          (define curve-max-len (apply max 0 (map string-length all-curve-vs)))
          (for ([curve (in-list all-curves)] [curve-v (in-list all-curve-vs)])
            (define aliases (remove curve (curve-name->aliases curve)))
            (cond [(null? aliases)
                   (printf " ~a\n" curve-v)]
                  [else
                   (printf " ~a  with aliases ~s\n"
                           (pad-to curve-v curve-max-len)
                           aliases)]))))
      ;; == EdDSA named curves ==
      (let ([all-curves (info 'all-eddsa-curves)])
        (when (pair? all-curves)
          (printf "Available 'eddsa named curves:\n")
          (for ([curve (in-list all-curves)])
            (printf " ~v\n" curve))))
      ;; == EC/X named curves ==
      (let ([all-curves (info 'all-ecx-curves)])
        (when (pair? all-curves)
          (printf "Available 'ecx named curves:\n")
          (for ([curve (in-list all-curves)])
            (printf " ~v\n" curve))))
      ;; == KDFs ==
      (let ([all-kdfs (info 'all-kdfs)])
        (when (pair? all-kdfs)
          (printf "Available KDFs:\n")
          (for ([kdf (in-list all-kdfs)] #:when (symbol? kdf))
            (printf " ~v\n" kdf))
          (let ([all-digests (info 'all-digests)])
            (cond [(null? all-digests) (void)]
                  [(for/and ([di (in-list all-digests)]) (get-kdf `(pbkdf2 hmac ,di)))
                   (printf " `(pbkdf2 hmac ,digest)  for all available digests\n")]
                  [else
                   (for ([di (in-list all-digests)] #:when (get-kdf `(pbkdf2 hmac ,di)))
                     (printf " ~v\n" `(pbkdf2 hmac ,di)))]))))
      (void))

    ;; table : Hash[*Spec => *Impl]
    ;; Note: assumes different *Spec types have disjoint values!
    ;; Only cache successful lookups to keep table size bounded.
    (field [table (make-hash)])

    (define-syntax-rule (get/table spec spec->key get-impl)
      ;; Note: spec should be variable reference
      (cond [(not ok?) #f]
            [(hash-ref table spec #f) => values]
            [(spec->key spec)
             => (lambda (key)
                  (cond [(get-impl key)
                         => (lambda (impl)
                              (hash-set! table (send impl get-spec) impl)
                              impl)]
                        [else #f]))]
            [else #f]))

    (define/public (get-digest spec)
      (get/table spec digest-spec->info -get-digest))
    (define/public (get-cipher spec)
      (get/table spec cipher-spec->info -get-cipher0))
    (define/public (get-pk spec)
      (get/table spec values -get-pk))
    (define/public (get-kdf spec)
      (get/table spec values -get-kdf))
    (define/public (get-pk-reader)
      (get/table '*pk-reader* values (lambda (k) (-get-pk-reader))))

    (define/public (-get-cipher0 info)
      (define ci (-get-cipher info))
      (cond [(cipher-impl? ci) ci]
            [(and (list? ci) (pair? ci) (andmap cdr ci))
             (new multikeylen-cipher-impl% (info info) (factory this) (impls ci))]
            [else #f]))

    ;; -get-digest : digest-info -> (U #f digest-impl)
    (define/public (-get-digest info) #f)

    ;; -get-cipher : cipher-info -> (U #f cipher-impl (listof (cons Nat cipher-impl)))
    (define/public (-get-cipher info) #f)

    ;; -get-pk : pk-spec -> (U pk-impl #f)
    (define/public (-get-pk spec) #f)

    ;; -get-pk-reader : -> (U pk-read-key #f)
    (define/public (-get-pk-reader) #f)

    ;; -get-kdf : -> (U kdf-impl #f)
    (define/public (-get-kdf spec) #f)
    ))

;; ============================================================
;; Digest

(define digest-impl%
  (class* info-impl-base% (digest-impl<%>)
    (inherit-field info)
    (inherit get-spec)
    (super-new)

    ;; Info methods
    (define/override (about) (format "~a digest" (super about)))
    (define/public (get-size) (send info get-size))
    (define/public (get-block-size) (send info get-block-size))
    (define/public (key-size-ok? keysize) (send info key-size-ok? keysize))

    (define/public (sanity-check #:size [size #f] #:block-size [block-size #f])
      ;; Use info::get-{block-,}size directly so that subclasses can
      ;; override get-size and get-block-size.
      (when size
        (unless (= size (send info get-size))
          (internal-error "digest size: expected ~s but got ~s\n  digest: ~a"
                          (send info get-size) size (about))))
      (when block-size
        (unless (= block-size (send info get-block-size))
          (internal-error "block size: expected ~s but got ~s\n  digest: ~a"
                          (send info get-block-size) block-size (about)))))

    (define/public (new-ctx key)
      (when key (check-key-size (bytes-length key)))
      (-new-ctx key))

    (define/public (check-key-size keysize)
      (unless (key-size-ok? keysize)
        (crypto-error "bad key size\n  key: ~s bytes\n  digest: ~a"
                      keysize (about))))

    (abstract -new-ctx)       ;; Bytes/#f -> digest-ctx<%>
    (abstract new-hmac-ctx)   ;; Bytes -> digest-ctx<%>

    (define/public (digest src key)
      (define (fallback) (send (new-ctx key) digest src))
      (when key (check-key-size (bytes-length key)))
      (cond [key (fallback)]
            [else
             (match src
               [(? bytes?) (or (-digest-buffer src 0 (bytes-length src)) (fallback))]
               [(bytes-range buf start end) (or (-digest-buffer buf start end) (fallback))]
               [_ (fallback)])]))

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

    (define/public (digest src)
      (update src)
      (final))

    (define/public (update src)
      (with-state #:ok '(open)
        (lambda () (void (process-input src (lambda (buf start end) (-update buf start end)))))))

    (define/public (final)
      (with-state #:ok '(open) #:post 'closed
        (lambda ()
          (define dest (make-bytes (send (get-impl) get-size)))
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
  (class* info-impl-base% (cipher-impl<%>)
    (inherit-field info)
    (inherit get-spec)
    (super-new)

    ;; Info methods
    (define/override (about) (format "~a cipher" (super about)))
    (define/public (get-cipher-name) (send info get-cipher-name))
    (define/public (get-mode) (send info get-mode))
    (define/public (get-type) (send info get-type))
    (define/public (aead?) (send info aead?))
    (define/public (get-block-size) (send info get-block-size))
    (define/public (get-chunk-size) (send info get-chunk-size))
    (define/public (get-key-size) (send info get-key-size))
    (define/public (get-key-sizes) (send info get-key-sizes))
    (define/public (key-size-ok? size) (size-set-contains? (get-key-sizes) size))
    (define/public (get-iv-size) (send info get-iv-size))
    (define/public (iv-size-ok? size) (send info iv-size-ok? size))
    (define/public (get-auth-size) (send info get-auth-size))
    (define/public (auth-size-ok? size) (send info auth-size-ok? size))
    (define/public (uses-padding?) (send info uses-padding?))

    (define/public (sanity-check #:block-size [block-size #f]
                                 #:chunk-size [chunk-size #f]
                                 #:iv-size [iv-size #f])
      (when block-size
        (unless (= block-size (send info get-block-size))
          (internal-error "block-size expected ~s but got ~s\n  cipher: ~a"
                          (send info get-block-size) block-size (about))))
      (when chunk-size
        (unless (= chunk-size (send info get-chunk-size))
          (internal-error "chunk-size expected ~s but got ~s\n  cipher: ~a"
                          (send info get-chunk-size) chunk-size (about))))
      (when iv-size
        (unless (iv-size-ok? iv-size)
          (internal-error "iv-size ~s not ok\n  cipher: ~a" iv-size (about))))
      (void))

    (define/public (new-ctx key iv enc? pad? auth-len0 attached-tag?)
      (check-key-size (bytes-length key))
      (check-iv-size (bytes-length (or iv #"")))
      (define auth-len (or auth-len0 (get-auth-size)))
      (check-auth-size auth-len)
      (let ([pad? (and pad? (uses-padding?))])
        (-new-ctx key iv enc? pad? auth-len attached-tag?)))

    (abstract -new-ctx)

    (define/public (check-key-size size)
      (unless (key-size-ok? size)
        (crypto-error "bad key size for cipher\n  cipher: ~a\n  given: ~e\n  allowed: ~a"
                      (about) size
                      (match (get-key-sizes)
                        [(? list? allowed)
                         (string-join (map number->string allowed) ", ")]
                        [(varsize min max step)
                         (format "from ~a to ~a in multiples of ~a" min max step)]))))

    (define/public (check-iv-size iv-size)
      (unless (iv-size-ok? iv-size)
        (crypto-error "bad IV size for cipher\n  cipher: ~a\n  expected: ~s bytes\n  got: ~s bytes"
                      (about) (get-iv-size) iv-size)))

    (define/public (check-auth-size auth-size)
      (unless (auth-size-ok? auth-size)
        (crypto-error "bad authentication tag size\n  cipher: ~a\n  given: ~e"
                      (about) auth-size)))
    ))

(define multikeylen-cipher-impl%
  (class cipher-impl-base%
    (init-field impls) ;; (nonempty-listof (cons nat cipher-impl%))
    (inherit-field info)
    (inherit about get-spec check-key-size)
    (super-new)

    (define/override (get-key-size) (caar impls))
    (define/override (get-key-sizes) (map car impls))

    (define/override (new-ctx key . args)
      (cond [(assoc (bytes-length key) impls)
             => (lambda (keylen+impl)
                  (send/apply (cdr keylen+impl) new-ctx key args))]
            [else
             (check-key-size (bytes-length key))
             (internal-error (string-append "no implementation for key length"
                                            "\n  cipher: ~a\n  given: ~s bytes\n  available: ~a")
                             (about) (bytes-length key)
                             (string-join (map number->string (map car impls)) ", "))]))
    (define/override (-new-ctx . args) (internal-error "unreachable"))
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
    (inherit with-state set-state about)
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
                 (crypto-error "wrong authentication tag size\n  expected: ~s\n  given: ~s\n  cipher: ~a"
                               auth-len (bytes-length tag) (about))))])
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
    (define/public (-make-aad-sink)
      (define (update inbuf instart inend) (-do-aad inbuf instart inend))
      (define (finish _ignored) (void))
      (sink-ufp update finish))

    (abstract -do-aad) ;; Bytes Nat Nat -> Void

    ;; -make-crypt-ufp : Boolean UFP -> UFP[Bytes,#f/AuthTag => AuthTag/#f]
    (define/public (-make-crypt-ufp enc? next)
      (define (update inbuf instart inend)
        ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
        (define outlen0 (+ (- inend instart) (get-block-size)))
        (define outbuf (make-bytes outlen0))
        (define outlen (-do-crypt enc? #f inbuf instart inend outbuf))
        (unless (= outlen (- inend instart))
          (internal-error "outlen = ~s, inlen = ~s" outlen (- inend instart)))
        (send next update outbuf 0 outlen))
      (define (finish partial auth-tag)
        ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
        (define outlen0 (* 2 (get-chunk-size)))
        (define outbuf (make-bytes outlen0))
        (define outlen (-do-crypt enc? #t partial 0 (bytes-length partial) outbuf))
        (unless (= outlen (bytes-length partial))
          (internal-error "outlen = ~s, partial = ~s" outlen (bytes-length partial)))
        (send next update outbuf 0 outlen)
        (cond [enc?
               (send next finish (-do-encrypt-end auth-len))]
              [else
               (unless (= (bytes-length auth-tag) auth-len)
                 (crypto-error "wrong authentication tag size\n  expected: ~s\n  given: ~s\n  cipher: ~a"
                               auth-len (bytes-length auth-tag) (about)))
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
;; KDF and Password Hashing

(define kdf-impl-base%
  (class* impl-base% (kdf-impl<%>)
    (super-new)
    (define/public (kdf params pass salt)
      (err/no-impl this))
    (define/public (pwhash params pass)
      (err/no-impl this))
    (define/public (pwhash-verify pass cred)
      (err/no-impl this))
    ))

(define (kdf-pwhash-argon2 ki config pass)
  (define-values (m t p)
    (check/ref-config '(m t p) config config:argon2-base "argon2"))
  (define alg (send ki get-spec))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((m ,m) (t ,t) (p ,p) (key-size 32)) pass salt))
  (pw:encode (hash '$id alg 'm m 't t 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-scrypt ki config pass)
  (define-values (ln p r)
    (check/ref-config '(ln p r) config config:scrypt-pwhash "scrypt"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32)) pass salt))
  (pw:encode (hash '$id 'scrypt 'ln ln 'r r 'p p 'salt salt 'pwhash pwh)))

(define (kdf-pwhash-pbkdf2 ki spec config pass)
  (define id (or (hash-ref pbkdf2-spec=>id spec #f)
                 (crypto-error "unsupported spec")))
  (define-values (iters)
    (check/ref-config '(iterations) config config:pbkdf2-base "PBKDF2"))
  (define salt (crypto-random-bytes 16))
  (define pwh (send ki kdf `((iterations ,iters) (key-size 32)) pass salt))
  (pw:encode (hash '$id id 'rounds iters 'salt salt 'pwhash pwh)))

(define pbkdf2-spec=>id
  (hash '(pbkdf2 hmac sha1)   'pbkdf2
        '(pbkdf2 hmac sha256) 'pbkdf2-sha256
        '(pbkdf2 hmac sha512) 'pbkdf2-sha512))

(define (kdf-pwhash-verify ki pass cred)
  (define spec (send ki get-spec))
  (define id (pw:peek-id cred))
  (unless (equal? spec (id->kdf-spec id))
    (crypto-error "kdf impl does not support cred id"))
  (define env (pw:parse cred))
  (define config
    (match env
      [(hash-table ['$id (or 'argon2i 'argon2d 'argon2id)] ['m m] ['t t] ['p p])
       `((m ,m) (t ,t) (p ,p) (key-size 32))]
      [(hash-table ['$id (or 'pbkdf2 'pbkdf2-sha256 'pbkdf2-sha512)] ['rounds rounds])
       `((iterations ,rounds) (key-size 32))]
      [(hash-table ['$id 'scrypt] ['ln ln] ['r r] ['p p])
       `((N ,(expt 2 ln)) (r ,r) (p ,p) (key-size 32))]))
  (define salt (hash-ref env 'salt))
  (define pwh (hash-ref env 'pwhash))
  (define pwh* (send ki kdf config pass salt))
  (crypto-bytes=? pwh pwh*))

(define (id->kdf-spec id)
  (case id
    [(argon2i argon2d argon2id scrypt) id]
    [(pbkdf2)        '(pbkdf2 hmac sha1)]
    [(pbkdf2-sha256) '(pbkdf2 hmac sha256)]
    [(pbkdf2-sha512) '(pbkdf2 hmac sha512)]
    [else #f]))

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

;; ----

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

;; ----

;; A Config is (listof (list Symbol Any))
(define config/c (listof (list/c symbol? any/c)))

;; A ConfigSpec is (listof ConfigSpecEntry)
;; A ConfigSpecEntry is one of
;; - (list Symbol Predicate String/#f '#:req)     -- required
;; - (list Symbol Predicate String/#f '#:opt Any) -- optional w/ default
;; - (list Symbol Predicate String/#f '#:alt Symbol) -- requires this or alt but not both

(define (check-config config spec what)
  ;; Assume already checked config/c, now check entries
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
                       what key config))
       config]
      [(list key _ _ '#:opt default)
       (if (assq key config)
           config
           (cons (list key default) config))]
      [(list key _ _ '#:alt key2)
       (if (assq key config)
           (when (assq key2 config)
             (crypto-error "conflicting options for ~a\n  options: ~e and ~e\n  given: ~e"
                           what key key2 config))
           (unless (assq key2 config)
             (crypto-error "missing required option for ~a\n  option: either ~e or ~e\n  given: ~e"
                           what key key2 config)))
       config])))

(define (config-ref config key [default #f])
  (cond [(assq key config) => (lambda (e) (or (cadr e) default))]
        [else default]))

(define (check/ref-config keys config spec what)
  (define config* (check-config config spec what))
  (apply values (for/list ([key (in-list keys)]) (config-ref config* key))))

;; ----

;; FIXME: make key-size a param to kdf instead?
(define config:kdf-key-size
  `((key-size   ,exact-positive-integer? #f #:opt 32)))

(define config:pbkdf2-base
  `((iterations ,exact-positive-integer? #f #:req)))

(define config:pbkdf2-kdf
  `(,@config:kdf-key-size
    ,@config:pbkdf2-base))

(define config:scrypt-pwhash
  `((ln ,exact-positive-integer? #f #:req)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:scrypt-kdf
  `(,@config:kdf-key-size
    (N  ,exact-positive-integer? #f #:alt ln)
    (ln ,exact-positive-integer? #f #:alt N)
    (p  ,exact-positive-integer? #f #:opt 1)
    (r  ,exact-positive-integer? #f #:opt 8)))

(define config:argon2-base
  `((t ,exact-positive-integer? #f #:req)
    (m ,exact-positive-integer? #f #:req)
    (p ,exact-positive-integer? #f #:opt 1)))

(define config:argon2-kdf
  `(,@config:kdf-key-size
    ,@config:argon2-base))

(define config:rsa-keygen
  `((nbits ,exact-positive-integer? #f #:opt 2048)
    (e     ,exact-positive-integer? #f #:opt #f)))

(define config:dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?"    #:opt 2048)
    (qbits ,(lambda (x) (member x '(160 256))) "(or/c 160 256)"  #:opt #f)))

(define config:dh-paramgen
  `((nbits     ,exact-positive-integer? #f                  #:opt 2048)
    (generator ,(lambda (x) (member x '(2 5))) "(or/c 2 5)" #:opt 2)))

(define config:ec-paramgen
  `((curve ,(lambda (x) (or (symbol? x) (string? x))) "(or/c symbol? string?)" #:req)))

(define config:eddsa-keygen
  `((curve ,(lambda (x) (memq x '(ed25519 ed448))) "(or/c 'ed25519 'ed448)" #:req)))

(define config:ecx-keygen
  `((curve ,(lambda (x) (memq x '(x25519 x448))) "(or/c 'x25519 'x448)" #:req)))

;; ----------------------------------------

;; version->list : String/#f -> (Listof Nat)/#f
(define (version->list str)
  (and str
       (if (regexp-match? #rx"^[0-9]+(?:[.][0-9]+)*$" str)
           (map string->number (string-split str #rx"[.]"))
           (internal-error "invalid version string: ~e" str))))

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
