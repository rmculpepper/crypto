;; Copyright 2012-2014 Ryan Culpepper
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
         get-output-size*
         cipher-segment-input
         whole-chunk-cipher-ctx%
         AE-whole-chunk-cipher-ctx%
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

    (define/public (with-state #:ok [ok-states #f] #:pre [pre-state #f] #:post [post-state #f]
                     #:msg [msg #f]
                     proc)
      (call-with-semaphore sema
        (lambda ()
          (when ok-states (unless (memq state ok-states) (bad-state state ok-states msg)))
          (when pre-state (unless (equal? state pre-state) (set! state pre-state)))
          (begin0 (proc)
            (when post-state (unless (equal? state post-state) (set! state post-state)))))))

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
        (lambda ()
          (let loop ([src src])
            (match src
              [(? bytes?) (void (-update src 0 (bytes-length src)))]
              [(bytes-range buf start end) (void (-update buf start end))]
              [(? input-port?)
               (process-input src (lambda (buf len) (-update buf 0 len)))]
              [(? string?)
               ;; Alternative: could process string in chunks like process-input.
               ;; Note: open-input-bytes makes copy, so can't just use that.
               (loop (string->bytes/utf-8 src))]
              [(? list?) (for ([sub (in-list src)]) (loop sub))])))))

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

    (define/public (get-block-size) (send (cdar impls) get-block-size))
    (define/public (get-iv-size) (send (cdar impls) get-iv-size))
    (define/public (get-default-key-size) (caar impls))
    (define/public (get-key-sizes) (map car impls))
    (define/public (get-auth-size) (send (cdar impls) get-auth-size))
    (define/public (get-chunk-size) (send (cdar impls) get-chunk-size))

    (define/public (new-ctx key iv enc? pad?)
      (cond [(assoc (bytes-length key) impls)
             => (lambda (keylen+impl)
                  (send (cdr keylen+impl) new-ctx key iv enc? pad?))]
            [else
             (check-key-size spec (bytes-length key))
             (error 'multikeylen-cipher-impl%
                    (string-append "internal error: no implementation for key length"
                                   "\n  cipher: ~e\n  given: ~s bytes\n  available: ~a")
                    spec (bytes-length key)
                    (string-join (map number->string (map car impls)) ", "))]))
    ))

(define whole-chunk-cipher-ctx%
  (class* ctx-base% (cipher-ctx<%>)
    (init-field encrypt? pad?)
    (inherit-field impl)
    (super-new)

    ;; Underlying impl only accepts whole chunks.
    ;; First partlen bytes of partial is waiting for rest of chunk.
    (field [block-size (send impl get-block-size)]
           [chunk-size (send impl get-chunk-size)]
           [partlen 0]
           [partial (make-bytes chunk-size)])

    (define/public (get-encrypt?) encrypt?)

    (define/public (get-output-size len final?)
      (get-output-size* len final? partlen block-size chunk-size encrypt? pad?))

    (define/public (update! inbuf instart inend outbuf outstart outend)
      (unless (*open?) (err/cipher-closed))
      (check-input-range inbuf instart inend)
      (define-values (prefixlen flush-partial? alignlen)
        (cipher-segment-input (- inend instart) partlen chunk-size encrypt? pad?))
      (define aligninstart (+ instart prefixlen))
      (define aligninend (+ aligninstart alignlen))
      (define pfxoutlen (if flush-partial? chunk-size 0))
      (define alignoutstart (+ outstart pfxoutlen))
      ;; Check output space
      (check-output-range outbuf outstart outend (+ pfxoutlen alignlen)
                          ;; FIXME: remove, like eprintf
                          #:msg (format "  ~s" (list instart inend
                                                     '/ partlen
                                                     '/ prefixlen flush-partial? alignlen)))
      ;; Process partial
      (when (< instart aligninstart)
        (bytes-copy! partial partlen inbuf instart aligninstart))
      (cond [flush-partial?
             (*crypt partial 0 chunk-size outbuf outstart (+ outstart chunk-size))
             (bytes-fill! partial 0)
             (set! partlen 0)]
            [else
             (set! partlen (+ partlen prefixlen))])
      ;; Process aligned
      (when (< aligninstart aligninend)
        (*crypt inbuf aligninstart aligninend outbuf alignoutstart (+ alignoutstart alignlen)))
      ;; Save leftovers
      (when (< aligninend inend)
        (bytes-copy! partial 0 inbuf aligninend inend)
        (set! partlen (- inend aligninend)))
      ;; Return total *written*
      (+ pfxoutlen alignlen))

    (define/public (final! outbuf outstart outend)
      (unless (*open?) (err/cipher-closed))
      (begin0
          (cond [encrypt?
                 (cond [pad?
                        (pad-bytes!/pkcs7 partial partlen)
                        (check-output-range outbuf outstart outend chunk-size)
                        (*crypt partial 0 chunk-size outbuf outstart outend)
                        chunk-size]
                       ;; [(zero? partlen) 0] ;; do *crypt-partial anyway (gcrypt ocb needs gcry_cipher_final)
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial))])]
                [else ;; decrypting
                 (cond [pad?
                        ;; Don't know actual output size until after decypted &
                        ;; de-padded, so require whole chunk of room.
                        (check-output-range outbuf outstart outend chunk-size)
                        (unless (= partlen chunk-size)
                          (err/partial))
                        (let ([tmp (make-bytes chunk-size)])
                          (*crypt partial 0 chunk-size tmp 0 chunk-size)
                          (let ([pos (unpad-bytes/pkcs7 tmp)])
                            (unless pos
                              (err/partial))
                            (bytes-copy! outbuf outstart tmp 0 pos)
                            pos))]
                       ;; [(zero? partlen) 0] ;; do *crypt-partial anyway (gcrypt ocb needs gcry_cipher_final)
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial))])])
        (*after-final)))

    ;; *crypt-partial : ... -> nat or #f
    ;; encrypt partial final chunk (eg for CTR mode)
    ;; returns number of bytes or #f to indicate refusal to handle partial chunk
    ;; only called if pad? is #f, (- inend instart) < chunk-size
    ;; Must do own check-output-range!
    (define/public (*crypt-partial inbuf instart inend outbuf outstart outend)
      #f)

    (define/private (err/partial)
      (crypto-error "partial chunk (~a)" (if encrypt? "encrypting" "decrypting")))

    (define/public (*after-final)
      (*close))

    (define/public (close)
      (*close))

    ;; Methods to implement in subclass:

    ;; *crypt : inbuf instart inend outbuf outstart outend -> void
    ;; encrypt/decrypt whole number of chunks
    (abstract *crypt)

    ;; *open? : -> boolean
    (abstract *open?)

    ;; *close : -> void
    (abstract *close)
    ))

(define AE-whole-chunk-cipher-ctx%
  (class whole-chunk-cipher-ctx%
    (inherit-field encrypt? pad? impl block-size chunk-size partlen partial)
    (super-new)

    (define AE? (cipher-spec-aead? (send impl get-spec)))

    ;; State is nat
    ;;  0 - needs tag set (decrypting)
    ;;  1 - ready for AAD
    ;;  2 - AAD done, ready for plaintext
    ;;  3 - finalized but tag available (encrypting)
    ;;  4 - closed
    (field [state (if (and (not encrypt?) AE?) 0 1)])

    (define/private (state-error state-desc)
      (crypto-error "cipher context sequence error\n  state: ~a" state-desc))

    (define/private (check-state ok-states #:next [new-state #f])
      (if (memq state ok-states)
          (when new-state (unless (= state new-state) (set! state new-state)))
          (case state
            [(0) (state-error "AE decryption context needs authentication tag")]
            [(1) (void)]
            [(2) (state-error "cannot add additionally authenticated data after plaintext")]
            [(3 4) (err/cipher-closed)])))

    ;; ----

    (define/override (update! inbuf instart inend outbuf outstart outend)
      (check-flush-AAD)
      (check-state '(1 2) #:next 2)
      (super update! inbuf instart inend outbuf outstart outend))

    (define/public (update-AAD inbuf instart inend)
      (check-state '(1))
      (define-values (prefixlen flush-partial? alignlen)
        (cipher-segment-input (- inend instart) partlen chunk-size #t #f))
      (define aligninstart (+ instart prefixlen))
      (define aligninend (+ aligninstart alignlen))
      (define pfxoutlen (if flush-partial? chunk-size 0))
      ;; Process partial
      (when (< instart aligninstart)
        (bytes-copy! partial partlen inbuf instart aligninstart))
      (cond [flush-partial?
             (*aad partial 0 chunk-size)
             (bytes-fill! partial 0)
             (set! partlen 0)]
            [else
             (set! partlen (+ partlen prefixlen))])
      ;; Process aligned
      (when (< aligninstart aligninend)
        (*aad inbuf aligninstart aligninend))
      ;; Save leftovers
      (when (< aligninend inend)
        (bytes-copy! partial 0 inbuf aligninend inend)
        (set! partlen (- inend aligninend)))
      (void))

    (define/override (final! outbuf outstart outend)
      (check-flush-AAD)
      (check-state '(1 2) #:next 3)
      (super final! outbuf outstart outend))

    (define/public (set-auth-tag tag)
      (check-state '(0) #:next 1)
      (*set-auth-tag tag))

    (define/public (get-auth-tag taglen)
      (unless encrypt?
        (crypto-error "cannot get authentication tag for decryption context"))
      (check-state '(3))
      (*get-auth-tag taglen))

    (define/override (*after-final)
      (unless AE? (*close)))

    (define/override (*close)
      (begin0 (super *close)
        (set! state 4)))

    (define/private (check-flush-AAD)
      (when (and (= state 1) (not (zero? partlen)))
        ;; flush AAD from partial
        (*aad partial 0 partlen)
        (set! partlen 0)))

    ;; *aad : bytes nat nat -> void
    (abstract *aad)

    ;; *set-auth-tag : bytes -> void
    (abstract *set-auth-tag)

    ;; *get-auth-tag : nat -> bytes
    (abstract *get-auth-tag)
    ))


;; get-output-size* : ... -> nat
(define (get-output-size* inlen final? partlen block-size chunk-size encrypt? pad?)
  (define-values (prefixlen flush-partial? alignlen)
    (cipher-segment-input inlen partlen chunk-size encrypt? pad?))
  (define pfxoutlen (if flush-partial? chunk-size 0))
  (define new-partlen
    (cond [(or flush-partial? (< (+ prefixlen alignlen) inlen))
           ;; flushed or skipped because empty
           (- inlen prefixlen alignlen)]
          [else (+ partlen prefixlen)]))
  (define for-update (+ pfxoutlen alignlen))
  (define for-final
    (cond [(not final?)
           0]
          [pad?
           ;; If pad?, assume chunk-size = block-size.
           ;; If encrypting:
           ;;   - new-partlen < chunk-size; no reason to buffer whole chunk when encrypting
           ;;   - result is new-partlen padded up to chunk-size, so chunk-size
           ;; If decrypting:
           ;;   - if new-partlen is full block, might de-pad to up to full block (chunk-size)
           ;;   - if partial, will fail to de-pad anyway
           chunk-size]
          [else ;; not pad?
           ;; If block cipher:
           ;;   - needs 0 bytes if new-partlen is 0
           ;;   - fails to de-pad otherwise, but block-size to be safe
           ;; If stream cipher:
           ;;   - needs new-partlen bytes
           (if (= new-partlen 0)
               0
               (max new-partlen block-size))]))
  (+ for-update for-final))

;; Divide an input buffer of length inlen into segments:
;;  - a prefix to fill a partial-buffer
;;    with a flag to indicate whether the partial-buffer can be emptied,
;;  - a chunk-multiple segment to process
;;  - (implicit) a leftover segment to put in the partial-buffer (overwriting start)
(define (cipher-segment-input inlen partlen chunk-size encrypt? pad?)
  ;; total = total material available
  (define total (+ partlen inlen))
  ;; First try to fill partial... except if was empty or full,
  ;; skip and go straight to aligned.
  ;; prefixlen = part of inlen to fill partial
  (define prefixlen
    (cond [(= partlen 0) 0]
          [else (min inlen (- chunk-size partlen))]))
  ;; Complication: when decrypting with padding, can't output
  ;; decrypted block until first byte of next block is seen, else
  ;; might miss ill-padded data.
  (define flush-partial?
    (and (positive? partlen)
         (if (or encrypt? (not pad?))
             (>= total chunk-size)
             (> total chunk-size))))
  ;; Then do aligned chunks: [alignstart, alignend) from in buffer
  ;; alignstart = start of inlen to process aligned
  (define alignstart prefixlen)
  (define alignend0 (- inlen (remainder (- inlen alignstart) chunk-size)))
  ;; Complication: like above
  (define alignend1
    (if (or encrypt? (not pad?))
        alignend0
        (if (> inlen alignend0)
            alignend0
            (- alignend0 chunk-size))))
  ;; alignend = end of inlen to process aligned
  (define alignend (max alignstart alignend1))
  (values prefixlen flush-partial? (- alignend alignstart)))

;; ============================================================
;; Input

(define DEFAULT-CHUNK 1000)

;; process-input : InputPort (Bytes Nat -> Void) -> Void
(define (process-input in process #:chunk [chunk-size DEFAULT-CHUNK])
  (define buf (make-bytes chunk-size))
  (let loop ()
    (define len (read-bytes! buf in))
    (unless (eof-object? len)
      (process buf len)
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
