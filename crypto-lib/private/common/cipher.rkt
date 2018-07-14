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
         racket/string
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")
(provide (all-defined-out))

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
        (crypto-error
         "bad key size for cipher\n  expected: ~s bytes\n  given: ~s bytes\n  cipher: ~a"
         (match (get-key-sizes)
           [(? list? allowed)
            (string-join (map number->string allowed) ", ")]
           [(varsize min max step)
            (format "from ~a to ~a in multiples of ~a" min max step)])
         size (about))))

    (define/public (check-iv-size iv-size)
      (unless (iv-size-ok? iv-size)
        (crypto-error
         "bad IV size for cipher\n  expected: ~s bytes\n  given: ~s bytes\n  cipher: ~a"
         (get-iv-size) iv-size (about))))

    (define/public (check-auth-size auth-size)
      (unless (auth-size-ok? auth-size)
        (crypto-error "bad authentication tag size\n  given: ~a bytes\n  cipher: ~a"
                      auth-size (about))))
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
             (check-key-size (bytes-length key)) ;; <- should raise error
             (internal-error "no implementation for given key size\n  cipher: ~a" (about))]))
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
    (define/override (describe-state state)
      (case state
        [(1) "ready for AAD or input"]
        [(2) "ready for input"]
        [(3) "closed"]))

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
               (check-bytes-length "authentication tag" auth-len tag this))])
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
                    [ufp (cond [pad? (pad-ufp (get-block-size) ufp)]
                               [(= (get-block-size) 1) ufp]
                               [else (check-aligned-ufp (get-block-size) impl ufp)])]
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
                    [ufp (cond [(= (get-block-size) 1) ufp]
                               [else (check-aligned-ufp (get-block-size) impl ufp)])]
                    [ufp (chunk-ufp (get-chunk-size) ufp)]
                    ;; FIXME: need to delay until we have auth-len ...
                    [ufp (if (and attached-tag? (positive? auth-len))
                             (pop-ufp (split-right-ufp auth-len ufp))
                             ufp)])
               ufp)]))
    ))


;; ============================================================
;; Padding

;; References:
;; http://en.wikipedia.org/wiki/Padding_%28cryptography%29
;; http://msdn.microsoft.com/en-us/library/system.security.cryptography.paddingmode.aspx
;; http://tools.ietf.org/html/rfc5246#page-22
;; http://tools.ietf.org/html/rfc5652#section-6.3

;; pad-bytes/pkcs7 : Bytes Nat -> Bytes
;; PRE: 0 < block-size < 256
(define (pad-bytes/pkcs7 buf block-size)
  (define padlen
    ;; if buf already block-multiple, must add whole block of padding
    (let ([part (remainder (bytes-length buf) block-size)])
      (- block-size part)))
  (bytes-append buf (make-bytes padlen padlen)))

;; unpad-bytes/pkcs7 : Bytes -> Bytes
(define (unpad-bytes/pkcs7 buf)
  (define buflen (bytes-length buf))
  (when (zero? buflen) (crypto-error "bad PKCS7 padding"))
  (define pad-length (bytes-ref buf (sub1 buflen)))
  (define pad-start (- buflen pad-length))
  (unless (and (>= pad-start 0)
               (for/and ([i (in-range pad-start buflen)])
                 (= (bytes-ref buf i) pad-length)))
    (crypto-error "bad PKCS7 padding"))
  (subbytes buf 0 pad-start))

;; Other kinds of padding, for reference
;; - ansix923: zeros, then pad-length for final byte
;; - pkcs5: IIUC, same as pkcs7 except for 64-bit blocks only
;; - iso/iec-7816-4: one byte of #x80, then zeros


;; ============================================================
;; UFP : Update/Finish Processors

;; Notionally, a functional UFP has the type
;;
;;   type UFP in out fin res = { update : in -> out, finish fin -> (out, res) }
;;
;; One natural notion of composition is chaining, which pipes the first
;; processor's output to the second's input and the first's result to the
;; second's finish argument:
;;
;;   chain : (UFP in out fin res) -> (UFP out out' res res') -> (UFP in out' fin res')
;;
;; A useful example is a UFP that receives bytes and forwards them in chunks
;; (bytestrings whose length is a multiple of some chunk-size parameter).
;;
;;   chunkUFP  : Nat -> (UFP Bytes Chunks () Bytes)
;;
;; If we pre-compose (chain . chunkUFP), we get something like
;;   chunkUFP' : Nat -> (UFP Chunks out' Bytes res') -> (UFP Bytes out' () res')

;; A useful pattern is fin/res polymorphism (cf concatenative langs?). Compare 
;;
;;   chunkUFP' : Nat -> (UFP Chunks out' Bytes res') -> (UFP Bytes out' () res')
;;   chunkUFP* : Nat -> (UFP Chunks out' (Bytes,a) res') -> (UFP Bytes out' a res')
;;
;; The chunkUFP* version takes any finish argument type and pushes its result
;; type onto the stack, allowing more flexible composition. A useful utility for
;; this pattern is
;;
;;   pop : UFP io io (a,b) b

;; The implementation below differs from this model in two significant ways.
;;
;; 1. Most UFP classes are written in chaining style (like chunkUFP' instead of
;;    chunkUFP).
;; 2. Output is handled imperatively. A UFP's update and finish methods do not
;;    return `out` results; they pass it to the next UFP's update method. This
;;    lets them represent IO as <buf,start,end>, which reduces copying.
;;
;; But they are documented as if they were the function, uncomposed versions.

;; ============================================================
;; Design of UFPs for crypto pipelines

;; Types of processors -- naturally divide into IN/OUT and FIN/RES; discuss separately

;; IN/OUT = <bytes nat nat>, but some produce/consume additional properties. In particular:
;;   chunk : bytes => chunks  -- introduces chunkedness
;;   pad   : prop => prop     -- preserves chunkedness
;;   unpad : chunks => bytes  -- destroys chunkedness
;;   *crypt: chunks => chunks
;;
;; writing (FIN => RES)
;;                  type                     actual inst in pipelines
;;   chunk        : a => bytes,a          ;; |a| = 1
;;   add-right    : bytes/#f,a => a       ;; |a| = 0,1
;;   split-right  : a => bytes,a          ;; |a| = 0,1
;;   pad          : bytes,a => bytes,a    ;; |a| = 1
;;   unpad        : bytes,a => bytes,a    ;; |a| = 1
;;   auth-encrypt : bytes,#f,a => tag,a   ;; |a| = 0
;;   auth-decrypt : bytes,tag,a => #f,a   ;; |a| = 0
;;   update-aad   : a => a                ;; |a| = 1 -- this choice allows chunk to be monomorphic!
;;   pop          : x,a => a              ;; |a| = 0
;;   push(x)      : a => x,a              ;; |a| = 0

;; Pipelines and types
;;
;; update-aad
;;   source -> chunk -> add-right -> update-aad -> sink
;;          #f       buf,#f       #f            #f
;;
;; encrypt (detached tag) =
;;   source -> chunk -> pad  -> auth-encrypt -> sink
;;          #f       buf,#f  buf,#f          tag
;;
;; decrypt (detached tag) =
;;   source -> chunk -> auth-decrypt -> split-right -> unpad -> add-right -> sink
;;          tag      buf,tag         #f             buf,#f   buf,#f       #f
;;
;; encrypt/attached-tag =
;;   source -> chunk -> pad  -> auth-encrypt -> add-right -> push #f -> sink
;;          #f       buf,#f  buf,#f          tag          ()         #f
;;
;; decrypt/attached-tag = 
;;   source -> pop -> split-right -> chunk -> pad  -> auth-decrypt -> sink
;;          #f     ()             tag      buf,tag buf,tag         #f

;; "Optimization": since chunk and split-right occur at start of pipeline, add
;; fused update/finish to recover simplicity for case when input is single
;; bytestring.

;; ============================================================

(define ufp<%>
  (interface ()
    update
    finish
    update/finish  ;; must not have called update before!
    ))

(define sink-ufp%
  (class* object% (ufp<%>)
    (init-field update-proc finish-proc)
    (super-new)
    (define/public (update buf start end) (update-proc buf start end))
    (define/public (finish . a) (apply finish-proc a))
    (define/public (update/finish buf start end . a)
      (update buf start end)
      (send/apply this finish a))))

(define chain-ufp%
  (class* object% (ufp<%>)
    (init-field next)
    (super-new)
    (define/public (update buf [start 0] [end (bytes-length buf)])
      (send next update buf start end))
    (define/public (finish . a)
      (send/apply next finish a))
    (define/public (update/finish buf start end . a)
      (update buf start end)
      (send/apply this finish a))))

;; ----

;; chunk        : a => bytes,a          ;; |a| = 1
(define chunk-ufp%
  (class chain-ufp%
    (init-field chunk-size)
    (inherit-field next)
    (field [partial (make-bytes chunk-size)]
           [partlen 0])
    (super-new)
    (define/override (update in [instart 0] [inend (bytes-length in)])
      (when (< instart inend)
        ;; in = A+B+C; A fills partial, B chunks, C leftover
        (define inlen (- inend instart))
        (define Alen (min inlen (- chunk-size partlen)))
        (bytes-copy! partial partlen in instart (+ instart Alen))
        (cond [(= (+ partlen Alen) chunk-size)
               (send next update partial 0 chunk-size)
               (set! partlen 0)]
              [else (set! partlen (+ partlen Alen))])
        (define BClen (- inlen Alen))
        (define Bstart (+ instart Alen))
        (define Blen (- BClen (remainder BClen chunk-size))) ;; multiple of chunk-size
        (define Cstart (+ Bstart Blen))
        (unless (zero? Blen)
          (send next update in Bstart (+ Bstart Blen)))
        (bytes-copy! partial partlen in Cstart inend)
        (set! partlen (+ partlen (- inend Cstart)))))
    (define/override (finish a)
      (define res (subbytes partial 0 partlen))
      (set! partlen 0)
      (send next finish res a))
    (define/override (update/finish in instart inend a)
      (define BClen (- inend instart))
      (define Blen (- BClen (remainder BClen chunk-size)))
      (unless (zero? Blen)
        (send next update in instart (+ instart Blen)))
      (define Cstart (+ instart Blen))
      (send next finish (subbytes in Cstart inend) a))))

;; chunk1       : a => bytes,a          ;; |a| = 1
;; Chunk specialized to chunk size of 1
(define chunk1-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish a)
      (send next finish #"" a))
    (define/override (update/finish in instart inend a)
      (send next update/finish in instart inend #"" a))))

;; add-right    : bytes/#f,a => a          ;; |a| = 0,1
(define add-right-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish buf . a)
      (when buf (send next update buf 0 (bytes-length buf)))
      (send/apply next finish a))))

;; split-right  : a => bytes,a          ;; |a| = 0,1
(define split-right-ufp%
  (class chain-ufp%
    (init-field suffix-size)
    (inherit-field next)
    (field [partial (make-bytes suffix-size)]
           [partlen 0])
    (super-new)
    (define/override (update in [instart 0] [inend (bytes-length in)])
      (define inlen (- inend instart))
      (cond [(= instart inend) (void)]
            [(< partlen suffix-size)
             (define Alen (min inlen (- suffix-size partlen)))
             (bytes-copy! partial partlen in instart (+ instart Alen))
             (set! partlen (+ partlen Alen))
             (update in (+ instart Alen) inend)]
            [else ;; partlen = suffix-size
             ;; How much of partial gets evicted? = (total - suffix), up to suffix (length of partial)
             (define evictlen (min inlen suffix-size))
             (unless (zero? evictlen)
               (send next update partial 0 evictlen)
               (bytes-copy! partial 0 partial evictlen suffix-size))
             ;; How much of in gets sent?
             ;; = (inlen - evictlen) = (inlen - min(inlen, suffix)) = max(0, inlen - suffix)
             (define sendlen (- inlen evictlen))
             (unless (zero? sendlen)
               (send next update in instart (+ instart sendlen)))
             (bytes-copy! partial (- suffix-size evictlen) in (+ instart sendlen) inend)]))
    (define/override (finish . a)
      (define r (subbytes partial 0 partlen))
      (set! partlen 0)
      (send/apply next finish r a))
    (define/override (update/finish in instart inend . a)
      (define inlen (- inend instart))
      (define ulen (max 0 (- inlen suffix-size)))
      (send/apply next update/finish in instart (+ instart ulen)
                  (subbytes (+ instart ulen) inend) a))))

;; check-aligned-ufp%
(define check-aligned-ufp%
  (class chain-ufp%
    (init-field block-size cipher)
    (inherit-field next)
    (super-new)
    (define/override (finish buf a)
      (unless (zero? (remainder (bytes-length buf) block-size))
        (crypto-error
         (string-append "input size not a multiple of block size"
                        "\n  block-size: ~s bytes\n  remainder: ~s bytes\n  cipher: ~a")
         block-size (remainder (bytes-length buf) block-size) (send cipher about)))
      (send next finish buf a))))

;; pad          : bytes,a => bytes,a    ;; |a| = 1
;; Add PKCS7 padding
;; FIXME: fix case when block-size != chunk-size
(define pad-ufp%
  (class chain-ufp%
    (init-field block-size)
    (inherit-field next)
    (super-new)
    (define/override (finish buf a)
      ;; Note: if buf is whole block, pads to 2 whole blocks.. problem?
      (send next finish (pad-bytes/pkcs7 buf block-size) a))))

;; unpad        : bytes,a => bytes,a    ;; |a| = 1
;; Check and remove PKCS7 padding
(define unpad-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish buf a)
      (send next finish (unpad-bytes/pkcs7 buf) a))))

;; pop          : x,a => a              ;; |a| = 0
(define pop-ufp%
  (class chain-ufp%
    (inherit-field next)
    (super-new)
    (define/override (finish v)
      (send next finish))
    (define/override (update/finish buf start end v)
      (send next update/finish buf start end))))

;; push(x)      : a => x,a              ;; |a| = 0
(define push-ufp%
  (class chain-ufp%
    (init-field value)
    (inherit-field next)
    (super-new)
    (define/override (finish)
      (send next finish value))))

;;   auth-encrypt : bytes,#f,a => tag,a   ;; |a| = 0
;;   auth-decrypt : bytes,tag,a => #f,a   ;; |a| = 0
;;   update-aad   : a => a                ;; |a| = 1 -- this choice allows chunk to be monomorphic!

;; ------------------------------------------------------------

(define (sink-ufp update-proc finish-proc)
  (new sink-ufp% (update-proc update-proc) (finish-proc finish-proc)))
(define (chunk-ufp chunk-size next)
  (if (= chunk-size 1)
      (new chunk1-ufp% (next next))
      (new chunk-ufp% (chunk-size chunk-size) (next next))))
(define (add-right-ufp next)
  (new add-right-ufp% (next next)))
(define (split-right-ufp suffix-size next)
  (new split-right-ufp% (suffix-size suffix-size) (next next)))
(define (check-aligned-ufp block-size cipher next)
  (new check-aligned-ufp% (block-size block-size) (cipher cipher) (next next)))
(define (pad-ufp block-size next)
  (new pad-ufp% (block-size block-size) (next next)))
(define (unpad-ufp next)
  (new unpad-ufp% (next next)))
(define (pop-ufp next)
  (new pop-ufp% (next next)))
(define (push-ufp value next)
  (new push-ufp% (value value) (next next)))
