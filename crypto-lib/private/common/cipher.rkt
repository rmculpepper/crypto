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
         "error.rkt"
         "ufp.rkt")
(provide cipher-impl-base%
         multikeylen-cipher-impl%
         cipher-ctx%)

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
