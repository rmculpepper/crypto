;; Copyright 2012-2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/string
         racket/contract/base
         brandx
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt")
(provide (contract-out
          [make-cipher
           (-> info? factory? (or/c cipher-inner-impl? lowlevel-cipher-impl? #f)
               (or/c cipher-impl? #f))]
          [make-multikeylen-cipher
           (-> info? factory? (listof (cons/c nat? (or/c lowlevel-cipher-impl? #f)))
               (or/c cipher-impl? #f))])
         (struct-out cipher-impl-base)
         (struct-out common-cipher-impl)
         (struct-out oneshot-cipher-inner-impl)
         (struct-out multikeylen-cipher-impl)
         (interface-out cipher-inner-impl$)
         (interface-out lowlevel-cipher-impl$)
         pad-bytes/pkcs7
         unpad-bytes/pkcs7)

(define (make-cipher info factory inner/llci)
  (match inner/llci
    [(? cipher-inner-impl? inner)
     (common-cipher-impl info factory inner)]
    [(? lowlevel-cipher-impl? llci)
     (define inner (ufp-cipher-inner-impl llci))
     (common-cipher-impl info factory inner)]
    [#f #f]))

(define (make-multikeylen-cipher info factory keylen+llci-list)
  (define keylen+ci-list
    (for/list ([keylen (in-list (map car keylen+llci-list))]
               [llci (in-list (map cdr keylen+llci-list))]
               #:when llci)
      (cons keylen (make-cipher info factory llci))))
  (and (pair? keylen+ci-list)
       (multikeylen-cipher-impl info factory keylen+ci-list)))

;; ============================================================
;; Cipher

(struct cipher-impl-base info-impl-base ()
  #:properties
  (method-properties
   #:export ([cipher-impl$ #:prefix %]
             [simple-write$ #:prefix %])
   #:import ([simple-write$ #:super])
   (define-struct-abbrevs cipher-impl-base)
   (define (%to-write-prefixes self)
     (list* "impl" "cipher" (super-to-write-prefixes self)))

   ;; ---- cipher-info

   ;; use fallbacks for ci-key-size-ok?
   (define (%ci-cipher-name self) ($ci-cipher-name (.info self)))
   (define (%ci-mode self) ($ci-mode (.info self)))
   (define (%ci-type self) ($ci-type (.info self)))
   (define (%ci-aead? self) ($ci-aead? (.info self)))
   (define (%ci-block-size self) ($ci-block-size (.info self)))
   (define (%ci-chunk-size self) ($ci-chunk-size (.info self)))
   (define (%ci-key-size self) ($ci-key-size (.info self)))
   (define (%ci-key-sizes self) ($ci-key-sizes (.info self)))
   (define (%ci-iv-size self) ($ci-iv-size (.info self)))
   (define (%ci-iv-size-ok? self size) ($ci-iv-size-ok? (.info self) size))
   (define (%ci-auth-size self) ($ci-auth-size (.info self)))
   (define (%ci-auth-size-ok? self size) ($ci-auth-size-ok? (.info self) size))
   (define (%ci-uses-padding? self) ($ci-uses-padding? (.info self)))
   ))

;; ----------------------------------------

(struct multikeylen-cipher-impl cipher-impl-base
  (impls    ;; (Listof (cons Nat CipherImpl))
   )
  #:properties
  (method-properties
   #:export ([cipher-impl$ #:prefix %])
   (define-struct-abbrevs multikeylen-cipher-impl)

   ;; ---- cipher-info

   (define (%ci-key-size self) (caar (.impls self)))
   (define (%ci-key-sizes self) (map car (.impls self)))

   ;; ---- cipher-impl

   (define (%ci-new-ctx self key iv enc? pad? auth-len attached-tag?)
     (match (assoc (bytes-length key) (.impls self))
       [(cons _ impl)
        ($ci-new-ctx impl key iv enc? pad? auth-len attached-tag?)]
       [#f (internal-error "no implementation for given key size" #:in self)]))
   ))

;; ----------------------------------------

(struct common-cipher-ctx cipher-ctx
  (pad?           ;; Boolean
   auth-len       ;; Nat -- 0 means no tag
   attached-tag?  ;; Boolean
   out            ;; BytesOutputPort
   auth-tag-box   ;; (Box (U Bytes #f))
   ))

(define cipher-state-desc
  '((aad    "ready for AAD or input")
    (open   "ready for input")
    (closed "closed")
    (error  "closed by error")))

(struct common-cipher-impl cipher-impl-base
  (inner    ;; CipherInnerImpl
   )
  #:properties
  (method-properties
   #:export ([cipher-impl$ #:prefix %]
             [simple-write$ #:prefix %])
   (define-struct-abbrevs common-cipher-impl)

   ;; ---- cipher-impl

   (define (%ci-new-ctx self key iv enc? pad? auth-len0 attached-tag?)
     (check-key-size self (bytes-length key))
     (check-iv-size self (bytes-length (or iv #"")))
     (define auth-len (or auth-len0 ($ci-auth-size self)))
     (check-auth-size self auth-len)
     (let ([pad? (and pad? ($ci-uses-padding? self))])
       (define out (open-output-bytes))
       (define auth-tag-box (box #f))
       (define ic ($cii-new-ctx (.inner self) self
                                key iv enc? pad? auth-len attached-tag?
                                out auth-tag-box))
       (define init-state (if ($ci-aead? self) 'aad 'open))
       (common-cipher-ctx self ic (make-statelock init-state cipher-state-desc)
                          enc? pad? auth-len attached-tag? out auth-tag-box)))

   (define (check-key-size self size)
     (unless ($ci-key-size-ok? self size)
       (crypto-error
        "bad key size for cipher\n  expected: ~s bytes\n  given: ~s bytes"
        (match ($ci-key-sizes self)
          [(? list? allowed)
           (string-join (map number->string allowed) ", ")]
          [(varsize min max step)
           (format "from ~a to ~a in multiples of ~a" min max step)])
        size #:in self)))

   (define (check-iv-size self iv-size)
     (unless ($ci-iv-size-ok? self iv-size)
       (crypto-error
        "bad IV size for cipher\n  expected: ~s bytes\n  given: ~s bytes"
        ($ci-iv-size self) iv-size #:in self)))

   (define (check-auth-size self auth-size)
     (unless ($ci-auth-size-ok? self auth-size)
       (crypto-error "bad authentication tag size\n  given: ~a bytes"
                     auth-size #:in self)))

   (define (%ci-update-aad self cctx src)
     (unless (null? src)
       (call-with-state
        cctx #:ok '(aad)
        (lambda (s) (update-aad* self cctx src)))))

   (define (update-aad* self cctx src)
     (define (process-aad buf start end)
       ($cii-update-aad (.inner self) (ctx-inner cctx) buf start end))
     (process-input src process-aad))

   (define (finish-aad* self cctx)
     ($cii-finish-aad (.inner self) (ctx-inner cctx)))

   (define (%ci-update self cctx src)
     (call-with-state
      cctx #:ok '(aad open) #:pre 'error #:post 'open
      (lambda (s)
        (when (member s '(aad))
          (finish-aad* self cctx))
        (update* self cctx src))))

   (define (update* self cctx src)
     (define (process-data buf start end)
       ($cii-update (.inner self) (ctx-inner cctx) buf start end))
     (process-input src process-data))

   (define (%ci-final self cctx auth-tag)
     (define encrypt? (cipher-ctx-encrypt? cctx))
     (define attached-tag? (common-cipher-ctx-attached-tag? cctx))
     (when (and encrypt? auth-tag)
       (crypto-error "cannot set authentication tag for encryption context"
                     #:for cctx))
     (when (and (not encrypt?) attached-tag? auth-tag)
       (crypto-error "cannot set authentication tag for decryption context with attached tag"
                     #:for cctx))
     (when (and (not encrypt?) (not attached-tag?))
       (let ([auth-tag (or auth-tag #"")]
             [auth-len (common-cipher-ctx-auth-len cctx)])
         (check-bytes "authentication tag" auth-tag auth-len #:for cctx)))
     (call-with-state
      cctx #:pre 'error #:post 'closed
      (lambda (s)
        (when (memq s '(aad))
          (finish-aad* self cctx))
        (when (memq s '(aad open))
          (final* self cctx auth-tag))
        (close* self cctx))))

   (define (final* self cctx auth-tag)
     ($cii-final (.inner self) (ctx-inner cctx) auth-tag))

   (define (close* self cctx)
     (when (ctx-inner cctx)
       ($cii-close (.inner self) (ctx-inner cctx))
       (set-ctx-inner! cctx #f)))

   (define (%ci-get-output self cctx)
     (get-output-bytes (common-cipher-ctx-out cctx)))

   (define (%ci-auth-tag self cctx)
     (cond [(cipher-ctx-encrypt? cctx)
            ;; ci-final sets auth-tag-out for encryption context
            ;; #"" for non-AEAD cipher
            (call-with-state
             cctx #:ok '(closed)
             (lambda (s) (get-auth-tag* self cctx)))]
           [else ;; decrypt
            (crypto-error "cannot get authentication tag for decryption context"
                          #:for cctx)]))

   (define (get-auth-tag* self cctx)
     (unbox (common-cipher-ctx-auth-tag-box cctx)))))

;; ============================================================
;; Cipher Inner Impl

(define-interface cipher-inner-impl$
  #:predicate cipher-inner-impl?
  ([cii-new-ctx
    (-> cipher-inner-impl? cipher-impl? key/c iv/c boolean?
        cipher-pad/c (or/c nat? #f) boolean? output-port? box?
        ictx/c)]
   [cii-update-aad
    (-> cipher-inner-impl? ictx/c bytes? nat? nat?
        void?)]
   [cii-finish-aad
    (-> cipher-inner-impl? ictx/c
        void?)]
   [cii-update
    (-> cipher-inner-impl? ictx/c bytes? nat? nat?
        void?)]
   [cii-final
    (-> cipher-inner-impl? ictx/c (or/c bytes? #f)
        void?)]
   [cii-close
    (-> cipher-inner-impl? ictx/c
        void?)])
  #:generics-prefix $)

;; ----------------------------------------
;; Oneshot Cipher Inner Impl

(struct oneshot-cipher-ctx
  (crypt        ;; (Bytes Bytes Bytes -> Void)
   aad-out      ;; BytesOutputPort
   text-out     ;; BytesOutputPort
   ))

(struct oneshot-cipher-inner-impl
  (encrypt    ;; Bool Bool Nat Bool Bytes Bytes Bytes Bytes -> (values Bytes Nat Bytes)
   decrypt    ;; Bool Bool Nat Bool Bytes Bytes Bytes Bytes -> (values Bytes Nat Bytes)
   )
  #:properties
  (method-properties
   #:export ([cipher-inner-impl$ #:prefix %])
   (define-struct-abbrevs oneshot-cipher-inner-impl)

   ;; ---- cipher-impl

   (define (%cii-new-ctx self ci key iv enc? pad? auth-len attached? out auth-box)
     (define aad-out (open-output-bytes))
     (define text-out (open-output-bytes))
     (cond [enc?
            (define (crypt* _ignored)
              (define aad (get-output-bytes aad-out #t))
              (define text (get-output-bytes text-out))
              (define-values (outbuf outlen auth-tag)
                ((.encrypt self) pad? key iv aad text auth-len))
              (write-bytes outbuf out 0 outlen)
              (cond [attached?
                     (write-bytes auth-tag out)
                     (set-box! auth-box #"")]
                    [else (set-box! auth-box auth-tag)]))
            (oneshot-cipher-ctx crypt* aad-out text-out)]
           [else
            (define (crypt* auth-tag1)
              (define aad (get-output-bytes aad-out #t))
              (define-values (text auth-tag)
                (cond [attached?
                       (define len (file-position text-out))
                       (when (< len auth-len)
                         (crypto-error "ciphertext too short"))
                       (define textlen (- len auth-len))
                       (define text (get-output-bytes text-out #f 0 textlen))
                       (define auth-tag (get-output-bytes text-out #t textlen #f))
                       (values text auth-tag)]
                      [else (values (get-output-bytes text-out) auth-tag1)]))
              (define-values (outbuf outlen)
                ((.decrypt self) pad? key iv aad text auth-tag))
              (write-bytes outbuf out 0 outlen)
              (set-box! auth-box #""))
            (oneshot-cipher-ctx crypt* aad-out text-out)]))

   (define (%cii-update-aad self ic buf start end)
     (write-bytes buf (oneshot-cipher-ctx-aad-out ic) start end)
     (void))

   (define (%cii-finish-aad self ic)
     (void))

   (define (%cii-update self ic buf start end)
     (write-bytes buf (oneshot-cipher-ctx-text-out ic) start end)
     (void))

   (define (%cii-final self ic auth-tag)
     ((oneshot-cipher-ctx-crypt ic) auth-tag))

   (define (%cii-close self ic)
     (void))
   ))

;; ----------------------------------------
;; UFP Cipher Inner Impl

(struct ufp-cipher-ctx (llc aad-ufp crypt-ufp))

(struct ufp-cipher-inner-impl
  (llci     ;; LowLevelCipherImpl
   )
  #:properties
  (method-properties
   #:export ([cipher-inner-impl$ #:prefix %])
   (define-struct-abbrevs ufp-cipher-inner-impl)

   ;; ----

   (define (%cii-new-ctx self ci key iv enc? pad? auth-len attached-tag? out auth-box)
     (define llc ($llci-new-ctx (.llci self) key iv enc? auth-len))
     (define aad-ufp (make-aad-ufp self ci llc))
     (define crypt-sink (make-output-sink out auth-box))
     (define crypt-ufp
       (make-crypt-ufp self ci llc enc? pad? auth-len attached-tag? crypt-sink))
     (ufp-cipher-ctx llc aad-ufp crypt-ufp))

   (define (%cii-update-aad self ic buf start end)
     ($uf-update (ufp-cipher-ctx-aad-ufp ic) buf start end))

   (define (%cii-finish-aad self ic)
     ($uf-finish (ufp-cipher-ctx-aad-ufp ic) null))

   (define (%cii-update self ic buf start end)
     ($uf-update (ufp-cipher-ctx-crypt-ufp ic) buf start end))

   (define (%cii-final self ic auth-tag)
     ($uf-finish (ufp-cipher-ctx-crypt-ufp ic) (list auth-tag)))

   (define (%cii-close self ic)
     ($llci-close (.llci self) (ufp-cipher-ctx-llc ic))
     (void))

   ;; ----

   (define (make-aad-ufp self ci llc)
     ;; update-aad
     ;;   source -> chunk -> add-right -> update-aad
     ;;          ()      (buf)         ()
     (define (do-aad buf start end)
       ($llci-aad (.llci self) llc buf start end)
       (void))
     (ufp~> (chunk-ufp ($ci-chunk-size ci))
            (add-right-ufp)
            #:base (sink-ufp do-aad void)))

   (define (make-crypt-ufp self ci llc enc? pad? auth-len attached-tag? sink)
     (if enc?
         (make-encrypt-ufp self ci llc pad? auth-len attached-tag? sink)
         (make-decrypt-ufp self ci llc pad? auth-len attached-tag? sink)))

   (define (make-encrypt-ufp self ci llc pad? auth-len attached-tag? sink)
     ;; encrypt (detached tag) =
     ;;   source -> chunk -> pad  -> auth-encrypt -> sink
     ;;         (#f)   (buf,#f) (buf,#f)        (tag)
     ;;
     ;; encrypt/attached-tag =
     ;;   source -> chunk -> pad  -> auth-encrypt -> add-right -> push #f -> sink
     ;;         (#f)   (buf,#f) (buf,#f)         (tag)         ()        (#f)
     (define block-size ($ci-block-size ci))
     (define chunk-size ($ci-chunk-size ci))
     (ufp~> (chunk-ufp chunk-size)
            (cond [pad? (pad-ufp block-size)]
                  [else (check-aligned-ufp block-size ci)])
            (lambda (ufp) (make-inner-crypt-ufp self ci llc #t auth-len ufp))
            (cond [attached-tag?
                   (ufp~> (add-right-ufp)
                          (push-ufp #f))]
                  [else values])
            #:base sink))

   (define (make-decrypt-ufp self ci llc pad? auth-len attached-tag? sink)
     ;; decrypt (detached tag) =
     ;;   source -> chunk -> auth-decrypt -> split-right -> unpad -> add-right -> sink
     ;;         (tag)  (buf,tag)         (#f)         (buf,#f)  (buf,#f)      (#f)
     ;;
     ;; decrypt/attached-tag =
     ;;   source -> pop -> split-right -> chunk  ->  auth-decrypt -> (...see above)
     ;;         ("")    ()            (tag)   (buf,tag)          (#f)
     (define block-size ($ci-block-size ci))
     (define chunk-size ($ci-chunk-size ci))
     (ufp~> (cond [(and attached-tag? (positive? auth-len))
                   (ufp~> (pop-ufp)
                          (split-right-ufp auth-len))]
                  [else values])
            (chunk-ufp chunk-size)
            (check-aligned-ufp block-size ci)
            (lambda (ufp) (make-inner-crypt-ufp self ci llc #f auth-len ufp))
            (cond [pad?
                   (ufp~> (split-right-ufp block-size)
                          (unpad-ufp)
                          (add-right-ufp))]
                  [else values])
            #:base sink))

   (define (make-inner-crypt-ufp self ci llc enc? auth-len next)
     (define llci (.llci self))
     (define block-size ($ci-block-size ci))
     (define chunk-size ($ci-chunk-size ci))
     (define (update inbuf instart inend)
       ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
       (define outlen0 (+ (- inend instart) block-size))
       (define outbuf (make-bytes outlen0))
       (define outlen
         ($llci-crypt llci llc enc? #f inbuf instart inend outbuf))
       (unless (= outlen (- inend instart))
         (internal-error "outlen = ~s, inlen = ~s" outlen (- inend instart) #:in ci))
       ($uf-update next outbuf 0 outlen))
     (define (finish a)
       (match-define (list partial auth-tag) a)
       ;; with block aligned and padding disabled, outlen = inlen... check, tighten (FIXME)
       (define outlen0 (* 2 chunk-size))
       (define outbuf (make-bytes outlen0))
       (define outlen
         ($llci-crypt llci llc enc? #t partial 0 (bytes-length partial) outbuf))
       (unless (= outlen (bytes-length partial))
         (internal-error "outlen = ~s, partial = ~s" outlen (bytes-length partial) #:in ci))
       ($uf-update next outbuf 0 outlen)
       (cond [enc?
              ($uf-finish next (list ($llci-encrypt-end llci llc auth-len)))]
             [else
              (unless (= (bytes-length auth-tag) auth-len)
                (crypto-error "wrong authentication tag size\n  expected: ~s\n  given: ~s"
                              auth-len (bytes-length auth-tag) #:in ci))
              ($llci-decrypt-end llci llc auth-tag)
              ($uf-finish next '(#f))]))
     (sink-ufp update finish))
   ))

;; ============================================================
;; Low-level Cipher Impl

(define-interface lowlevel-cipher-impl$
  #:predicate lowlevel-cipher-impl?
  ([llci-new-ctx
    (-> lowlevel-cipher-impl? key/c iv/c boolean? nat?
        ictx/c)]
   [llci-aad
    (-> lowlevel-cipher-impl? ictx/c bytes? nat? nat?
        any)]
   [llci-crypt ;; booleans are (enc? final?)
    (-> lowlevel-cipher-impl? ictx/c boolean? boolean? bytes? nat? nat? bytes?
        nat?)]
   [llci-encrypt-end
    (-> lowlevel-cipher-impl? ictx/c nat?
        bytes?)]
   [llci-decrypt-end ;; auth-tag size already checked
    (-> lowlevel-cipher-impl? ictx/c bytes?
        any)]
   [llci-close
    (-> lowlevel-cipher-impl? ictx/c
        any)])
  #:generics-prefix $)

(struct common-lowlevel-cipher-impl
  (new-ctx do-aad do-crypt do-encrypt-end do-decrypt-end do-close)
  #:properties
  (method-properties
   #:export ([lowlevel-cipher-impl$ #:prefix %])
   (define-struct-abbrevs common-lowlevel-cipher-impl)
   ;; ----
   (define (%llci-new-ctx self key iv enc? auth-len)
     ((.new-ctx self) key iv enc? auth-len))
   (define (%llci-aad self llc buf start end)
     ((.do-aad self) llc buf start end))
   (define (%llci-crypt self llc enc? final? buf start end outbuf)
     ((.do-crypt self) llc enc? final? buf start end outbuf))
   (define (%llci-encrypt-end self llc auth-len)
     ((.do-encrypt-end self) llc auth-len))
   (define (%llci-decrypt-end self llc auth-tag)
     ((.do-decrypt-end self) llc auth-tag))
   (define (%llci-close self llc)
     ((.do-close self) llc))))

#;
(define (cipher-sanity-check #:block-size [block-size #f]
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

(define-interface ufp$
  ([uf-update (-> ufp$? bytes? nat? nat? void?)]
   [uf-finish (-> ufp$? list? any)]
   [uf-update/finish (-> ufp$? bytes? nat? nat? list? any)])
  #:fallbacks
  (let ()
    (define (uf-update/finish self buf start end a)
      ($uf-update self buf start end)
      ($uf-finish self a))
    (hasheq 'uf-update/finish uf-update/finish))
  #:generics-prefix $)

(struct ufp:sink (update-proc finish-proc)
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:sink)
   (define (%uf-update self buf start end)
     ((.update-proc self) buf start end)
     (void))
   (define (%uf-finish self a)
     ((.finish-proc self) a))))

(struct ufp:chain (next)
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:chain)
   (define (%uf-update self buf start end)
     ($uf-update (.next self) buf start end))
   (define (%uf-finish self a)
     ($uf-finish (.next self) a))))

;; chunk        : a => bytes,a          ;; |a| = 1
(define (make-ufp:chunk next chunk-size)
  (ufp:chunk next chunk-size (make-bytes chunk-size) 0))

(struct ufp:chunk ufp:chain (chunk-size partial [partlen #:mutable])
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:chunk)

   (define (%uf-update self in instart inend)
     (match-define (ufp:chunk next chunk-size partial partlen0) self)
     (when (< instart inend)
       ;; in = A+B+C; A fills partial, B chunks, C leftover
       (define inlen (- inend instart))
       (define Alen (min inlen (- chunk-size partlen0)))
       (bytes-copy! partial partlen0 in instart (+ instart Alen))
       (cond [(= (+ partlen0 Alen) chunk-size)
              ($uf-update next partial 0 chunk-size)
              (.partlen-set! self 0)]
             [else (.partlen-set! self (+ partlen0 Alen))])
       (define BClen (- inlen Alen))
       (define Bstart (+ instart Alen))
       (define Blen (- BClen (remainder BClen chunk-size))) ;; multiple of chunk-size
       (define Cstart (+ Bstart Blen))
       (unless (zero? Blen)
         ($uf-update next in Bstart (+ Bstart Blen)))
       (bytes-copy! partial (.partlen self) in Cstart inend)
       (.partlen-set! self (+ (.partlen self) (- inend Cstart)))))

   (define (%uf-finish self a)
     (match-define (ufp:chunk next _ partial partlen0) self)
     (define res (subbytes partial 0 partlen0))
     (.partlen-set! self 0)
     ($uf-finish next (cons res a)))))

;; chunk1       : a => bytes,a          ;; |a| = 1
;; Chunk specialized to chunk size of 1
(struct ufp:chunk1 ufp:chain ()
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:chunk1)
   (define (%uf-finish self a)
     ($uf-finish (.next self) (cons #"" a)))
   (define (%uf-update/finish self in instart inend a)
     ($uf-update/finish (.next self) in instart inend (cons #"" a)))))

;; add-right    : bytes/#f,a => a          ;; |a| = 0,1
(struct ufp:add-right ufp:chain ()
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define (%uf-finish self a1)
     (match-define (ufp:add-right next) self)
     (match-define (cons buf a) a1)
     (when buf ($uf-update next buf 0 (bytes-length buf)))
     ($uf-finish next a))))

;; split-right  : a => bytes,a          ;; |a| = 0,1
(define (make-ufp:split-right next suffix-size)
  (ufp:split-right next suffix-size (make-bytes suffix-size) 0))

(struct ufp:split-right ufp:chain (suffix-size partial [partlen #:mutable])
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:split-right)

   (define (%uf-update self in instart inend)
     (match-define (ufp:split-right next suffix-size partial partlen0) self)
     (define inlen (- inend instart))
     (cond [(= instart inend) (void)]
           [(< partlen0 suffix-size)
            (define Alen (min inlen (- suffix-size partlen0)))
            (bytes-copy! partial partlen0 in instart (+ instart Alen))
            (.partlen-set! self (+ partlen0 Alen))
            ($uf-update next in (+ instart Alen) inend)]
           [else ;; partlen = suffix-size
            ;; How much of partial gets evicted?
            ;; Evict (total - suffix), up to suffix (length of partial).
            (define evictlen (min inlen suffix-size))
            (unless (zero? evictlen)
              ($uf-update next partial 0 evictlen)
              (bytes-copy! partial 0 partial evictlen suffix-size))
            ;; How much of in gets sent?
            ;; = (inlen - evictlen) = (inlen - min(inlen, suffix)) = max(0, inlen - suffix)
            (define sendlen (- inlen evictlen))
            (unless (zero? sendlen)
              ($uf-update next in instart (+ instart sendlen)))
            (bytes-copy! partial (- suffix-size evictlen) in (+ instart sendlen) inend)]))

   (define (%uf-finish self a)
     (match-define (ufp:split-right next _ partial partlen0) self)
     (define r (subbytes partial 0 partlen0))
     (.partlen-set! self 0)
     ($uf-finish (.next self) (cons r a)))

   (define (%uf-update/finish self in instart inend a)
     (match-define (ufp:split-right next suffix-size partial partlen0) self)
     (define inlen (- inend instart))
     (define ulen (max 0 (- inlen suffix-size)))
     ($uf-update/finish next in instart (+ instart ulen)
                        (cons (subbytes (+ instart ulen) inend) a)))))

;; check-aligned : bytes,a => bytes,a
(struct ufp:check-aligned ufp:chain (block-size cipher)
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   ;; FIXME: update should also check multiple of block size?
   (define (%uf-finish self a1)
     (match-define (ufp:check-aligned next block-size cipher) self)
     (match-define (cons buf a) a1)
     (unless (zero? (remainder (bytes-length buf) block-size))
       (crypto-error
        (string-append "input size not a multiple of block size"
                       "\n  block-size: ~s bytes\n  remainder: ~s bytes")
        block-size (remainder (bytes-length buf) block-size) #:for cipher))
     ($uf-finish next a1))))

;; pad          : bytes,a => bytes,a    ;; |a| = 1
;; Add PKCS7 padding
;; FIXME: fix case when block-size != chunk-size
(struct ufp:pad ufp:chain (block-size)
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define (%uf-finish self a1)
     (match-define (cons buf a) a1)
     (match-define (ufp:pad next block-size) self)
     ;; Note: if buf is whole block, pads to 2 whole blocks
     ($uf-finish next (cons (pad-bytes/pkcs7 buf block-size) a)))))

;; unpad        : bytes,a => bytes,a    ;; |a| = 1
;; Check and remove PKCS7 padding
(struct ufp:unpad ufp:chain ()
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define (%uf-finish self a1)
     (match-define (ufp:unpad next) self)
     (match-define (cons buf a) a1)
     ($uf-finish next (cons (unpad-bytes/pkcs7 buf) a)))))

;; pop          : x,a => a              ;; |a| = 0
(struct ufp:pop ufp:chain ()
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:pop)
   (define (%uf-finish self a)
     ($uf-finish (.next self) (cdr a)))
   (define (%uf-update/finish self buf start end a)
     ($uf-finish (.next self) buf start end (cdr a)))))

;; push(x)      : a => x,a              ;; |a| = 0
(struct ufp:push ufp:chain (value)
  #:properties
  (method-properties
   #:export ([ufp$ #:prefix %])
   (define-struct-abbrevs ufp:push)
   (define (%uf-finish self a)
     (match-define (ufp:push next value) self)
     ($uf-finish next (cons value a)))))

;;   auth-encrypt : bytes,#f,a => tag,a   ;; |a| = 0
;;   auth-decrypt : bytes,tag,a => #f,a   ;; |a| = 0
;;   update-aad   : a => a                ;; |a| = 1

;; ------------------------------------------------------------

(define (sink-ufp update-proc finish-proc)
  (ufp:sink update-proc finish-proc))
(define ((chunk-ufp chunk-size) next)
  (if (= chunk-size 1) (ufp:chunk1 next) (make-ufp:chunk next chunk-size)))
(define ((add-right-ufp) next)
  (ufp:add-right next))
(define ((split-right-ufp suffix-size) next)
  (make-ufp:split-right next suffix-size))
(define ((check-aligned-ufp block-size cipher) next)
  (if (= block-size 1) next (ufp:check-aligned next block-size cipher)))
(define ((pad-ufp block-size) next)
  (ufp:pad next block-size))
(define ((unpad-ufp) next)
  (ufp:unpad next))
(define ((pop-ufp) next)
  (ufp:pop next))
(define ((push-ufp value) next)
  (ufp:push next value))

;; make-output-sink : -> UFP[Any => ]
(define (make-output-sink out finish-box)
  (sink-ufp (lambda (buf start end) (write-bytes buf out start end))
            (lambda (a) (when finish-box (set-box! finish-box (car a))))))

(define (ufp~> #:base [base #f] . fs)
  (define (ufp-compose fs base)
    (for/fold ([base base]) ([f (in-list (reverse fs))]) (f base)))
  (cond [base (ufp-compose fs base)]
        [else (lambda (base) (ufp-compose fs base))]))
