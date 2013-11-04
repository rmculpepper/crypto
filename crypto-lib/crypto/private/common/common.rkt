;; Copyright 2012 Ryan Culpepper
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
         racket/string
         "catalog.rkt"
         "interfaces.rkt"
         "../rkt/padding.rkt")
(provide base-ctx%
         factory-base%
         multikeylen-cipher-impl%
         whole-block-cipher-ctx%
         shrink-bytes)

;; ----

(define base-ctx%
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

    (define/public (get-digest spec)
      (cond [(hash-ref digest-table spec #f)
             => (lambda (impl/none)
                  (and (digest-impl? impl/none) impl/none))]
            [else
             (let ([di (get-digest* spec)])
               (when di (hash-set! digest-table spec di))
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
                                         (impls ci/s)))]
                              [(cipher-impl? ci/s) ci/s]
                              [else #f])])
               (when ci (hash-set! cipher-table spec ci))
               ci)]))

    (define/public (get-pkey spec) #f)
    (define/public (get-random) #f)

    (abstract get-digest*)
    (abstract get-cipher*) ;; CipherSpec -> (U #f CipherImpl (listof (cons nat CipherImpl)))
    ))

;; ----

(define multikeylen-cipher-impl%
  (class* object% (cipher-impl<%>)
    (init-field impls ;; (nonempty-listof (cons nat cipher-impl%))
                spec)
    (super-new)

    (define/public (get-spec) spec)
    (define/public (get-block-size) (send (car impls) get-block-size))
    (define/public (get-iv-size) (send (car impls) get-iv-size))

    (define/public (new-ctx who key iv enc? pad?)
      (cond [(assoc (bytes-length key) impls)
             => (lambda (keylen+impl)
                  (send (cdr keylen+impl) new-ctx who key iv enc? pad?))]
            [else
             (check-key-size who spec (bytes-length key))
             (error 'multikeylen-cipher-impl%
                    (string-append "internal error: no implementation for key length"
                                   "\n  cipher: ~e\n  given: ~s bytes\n  available: ~a")
                    spec (bytes-length key)
                    (string-join (map number->string (map car impls)) ", "))]))
    ))

;; ----

(define whole-block-cipher-ctx%
  (class* base-ctx% (cipher-ctx<%>)
    (init-field encrypt? pad?)
    (inherit-field impl)
    (super-new)

    ;; Underlying impl only accepts whole blocks.
    ;; First partlen bytes of partial is waiting for rest of block.
    (field [block-size (send impl get-block-size)])
    (define partial (make-bytes block-size))
    (define partlen 0)

    (define/public (get-encrypt?) encrypt?)

    (define/public (update! who inbuf instart inend outbuf outstart outend)
      (unless (*open?) (error who "cipher context is closed"))
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
      (when (< instart alignstart)
        (bytes-copy! partial partlen inbuf instart alignstart))
      (cond [flush-partial?
             (*crypt partial 0 block-size outbuf outstart (+ outstart block-size)) ;; outend
             (bytes-fill! partial 0)
             (set! partlen 0)]
            [else
             (set! partlen (+ partlen prefixlen))])
      (define outstart* (+ outstart pfxoutlen))
      (define alignlen (- alignend alignstart))
      (when (< alignstart alignend)
        (*crypt inbuf alignstart alignend outbuf outstart* (+ outstart* alignlen))) ;; outend
      (when (< alignend inend) ;; implies flush-partial?
        (bytes-copy! partial 0 inbuf alignend inend)
        (set! partlen (- inend alignend)))
      (+ pfxoutlen alignlen))

    (define/public (final! who outbuf outstart outend)
      (unless (*open?) (error who "cipher context is closed"))
      (begin0
          (cond [encrypt?
                 (cond [pad?
                        (pad-bytes!/pkcs7 partial partlen)
                        (*crypt partial 0 block-size outbuf outstart outend)
                        block-size]
                       [(zero? partlen)
                        0]
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial who))])]
                [else ;; decrypting
                 (cond [pad?
                        (unless (= partlen block-size)
                          (err/partial who))
                        (let ([tmp (make-bytes block-size)])
                          (*crypt partial 0 block-size tmp 0 block-size)
                          (let ([pos (unpad-bytes/pkcs7 tmp)])
                            (unless pos
                              (err/partial who))
                            (bytes-copy! outbuf outstart tmp 0 pos)
                            pos))]
                       [(zero? partlen)
                        0]
                       [else
                        (or (*crypt-partial partial 0 partlen outbuf outstart outend)
                            (err/partial who))])])
        (*close)))

    ;; *crypt-partial : ... -> nat or #f
    ;; encrypt partial final block (eg for CTR mode)
    ;; returns number of bytes or #f to indicate refusal to handle partial block
    ;; only called if pad? is #f, (- inend instart) < block-size
    (define/public (*crypt-partial inbuf instart inend outbuf outstart outend)
      #f)

    (define/private (err/partial who)
      (error who "partial block (~a)" (if encrypt? "encrypting" "decrypting")))

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

(define (shrink-bytes bs len)
  (if (< len (bytes-length bs))
    (subbytes bs 0 len)
    bs))
