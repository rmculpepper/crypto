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
         racket/contract/base
         racket/string
         "catalog.rkt"
         "interfaces.rkt"
         "error.rkt"
         "factory.rkt"
         "../rkt/padding.rkt")
(provide impl-base%
         ctx-base%
         factory-base%
         multikeylen-cipher-impl%
         whole-block-cipher-ctx%
         get-impl*
         get-spec*
         get-factory*
         get-random*
         shrink-bytes
         keygen-spec/c
         check-keygen-spec
         keygen-spec-ref)

;; ----

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

;; ----

(define factory-base%
  (class* object% (factory<%>)
    (super-new)

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
    (define/public (get-random) #f)

    (define/public (get-digest* spec) #f) ;; -> (U #f DigestImpl)
    (define/public (get-cipher* spec) #f) ;; -> (U #f CipherImpl (listof (cons nat CipherImpl)))
    (define/public (get-pk* spec) #f)   ;; -> (U #f DigestIpl
    ))

;; ----

(define multikeylen-cipher-impl%
  (class* impl-base% (cipher-impl<%>)
    (init-field impls) ;; (nonempty-listof (cons nat cipher-impl%))
    (inherit-field spec)
    (super-new)

    (define/public (get-block-size) (send (cdar impls) get-block-size))
    (define/public (get-iv-size) (send (cdar impls) get-iv-size))

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

;; ----

(define whole-block-cipher-ctx%
  (class* ctx-base% (cipher-ctx<%>)
    (init-field encrypt? pad?)
    (inherit-field impl)
    (super-new)

    ;; Underlying impl only accepts whole blocks.
    ;; First partlen bytes of partial is waiting for rest of block.
    (field [block-size (send impl get-block-size)])
    (define partial (make-bytes block-size))
    (define partlen 0)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! inbuf instart inend outbuf outstart outend)
      (unless (*open?) (err/cipher-closed))
      (check-input-range inbuf instart inend)
      (define len (- inend instart))
      (define total (+ len partlen))
      ;; First complete fill partial to *crypt separately
      ;; ... except if was empty, skip and go straight to aligned
      (define prefixlen (remainder (min len (- block-size partlen)) block-size))
      ;; Complication: when decrypting with padding, can't output decrypted block until
      ;; first byte of next block is seen, else might miss ill-padded data.
      (define flush-partial?
        (and (positive? partlen)
             (if (or encrypt? (not pad?))
                 (>= total block-size)
                 (> total block-size))))
      ;; Then do aligned blocks: [alignstart,alignend)
      (define alignstart (+ instart prefixlen))
      (define alignend0 (- inend (remainder (- inend alignstart) block-size)))
      (define alignend1
        (if (or encrypt? (not pad?))
            alignend0
            (if (zero? (remainder (- alignend0 alignstart) block-size))
                (- alignend0 block-size)
                alignend0)))
      (define alignend (max alignstart alignend1))
      (define pfxoutlen (if flush-partial? block-size 0))
      (define outstart* (+ outstart pfxoutlen))
      (define alignlen (- alignend alignstart))
      ;; Total output space needed:
      (check-output-range outbuf outstart outend (+ pfxoutlen alignlen))
      (when (< instart alignstart)
        (bytes-copy! partial partlen inbuf instart alignstart))
      (cond [flush-partial?
             (*crypt partial 0 block-size outbuf outstart (+ outstart block-size)) ;; outend
             (bytes-fill! partial 0)
             (set! partlen 0)]
            [else
             (set! partlen (+ partlen prefixlen))])
      (when (< alignstart alignend)
        (*crypt inbuf alignstart alignend outbuf outstart* (+ outstart* alignlen))) ;; outend
      (when (< alignend inend) ;; implies flush-partial?
        (bytes-copy! partial 0 inbuf alignend inend)
        (set! partlen (- inend alignend)))
      (+ pfxoutlen alignlen))

    (define/public (final! outbuf outstart outend)
      (unless (*open?) (err/cipher-closed))
      (begin0
          (cond [encrypt?
                 (cond [pad?
                        (pad-bytes!/pkcs7 partial partlen)
                        (check-output-range outbuf outstart outend block-size)
                        (*crypt partial 0 block-size outbuf outstart outend)
                        block-size]
                       [(zero? partlen)
                        0]
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial))])]
                [else ;; decrypting
                 (cond [pad?
                        ;; Don't know actual output size until after decypted &
                        ;; de-padded, so require whole block of room.
                        (check-output-range outbuf outstart outend block-size)
                        (unless (= partlen block-size)
                          (err/partial))
                        (let ([tmp (make-bytes block-size)])
                          (*crypt partial 0 block-size tmp 0 block-size)
                          (let ([pos (unpad-bytes/pkcs7 tmp)])
                            (unless pos
                              (err/partial))
                            (bytes-copy! outbuf outstart tmp 0 pos)
                            pos))]
                       [(zero? partlen)
                        0]
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial))])])
        (*close)))

    ;; *crypt-partial : ... -> nat or #f
    ;; encrypt partial final block (eg for CTR mode)
    ;; returns number of bytes or #f to indicate refusal to handle partial block
    ;; only called if pad? is #f, (- inend instart) < block-size
    ;; Must do own check-output-range!
    (define/public (*crypt-partial inbuf instart inend outbuf outstart outend)
      #f)

    (define/private (err/partial)
      (crypto-error "partial block (~a)" (if encrypt? "encrypting" "decrypting")))

    (define/public (close)
      (*close))

    ;; Methods to implement in subclass:

    ;; *crypt : inbuf instart inend outbuf outstart outend -> void
    ;; encrypt/decrypt whole number of blocks
    (abstract *crypt)

    ;; *open? : -> boolean
    (abstract *open?)

    ;; *close : -> void
    (abstract *close)
    ))

;; ----

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

(define (get-random* src)
  (let ([random-impl
         (if src
             (send (get-factory* src) get-random)
             (get-random))])
    (or random-impl
        (crypto-error "no source of randomness available~a"
                      (if src
                          (format "\n  from: ~e" src)
                          "")))))

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
