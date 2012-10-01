;; mzcrypto: libcrypto bindings for PLT-scheme
;; message digests
;; 
;; (C) Copyright 2007-2009 Dimitris Vyzovitis <vyzo at media.mit.edu>
;; 
;; mzcrypto is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; mzcrypto is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with mzcrypto.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require ffi/unsafe
         racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "macros.rkt"
         "rand.rkt"
         "util.rkt"
         (only-in racket/list last)
         (for-syntax racket/base
                     racket/syntax))

;; FIXME: potential races all over the place

;; ============================================================

(define digest-impl%
  (class* object% (digest-impl<%>)
    (init-field md    ;; EVP_MD
                name) ;; symbol
    (define size (last (ptr-ref md (_list-struct _int _int _int))))
    (super-new)

    (define/public (get-name) (symbol->string name))
    (define/public (get-size) size)

    (define/public (new-ctx)
      (let ([ctx (EVP_MD_CTX_create)])
        (EVP_DigestInit_ex ctx md)
        (new digest-ctx% (impl this) (ctx ctx))))
    ))


(define digest-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)

    (super-new)

    (define/public (update! who buf start end)
      (unless ctx (error who "digest context is closed"))
      (check-input-range who buf start end)
      (EVP_DigestUpdate ctx (ptr-add buf start) (- end start)))

    (define/public (final! who buf start end)
      (unless ctx (error who "digest context is closed"))
      (let ([size (send impl get-size)])
        (check-output-range who buf start end size)
        (EVP_DigestFinal_ex ctx (ptr-add buf start))
        (EVP_MD_CTX_destroy ctx)
        (set! ctx #f)
        size))

    (define/public (copy who)
      (and ctx
           (let ([other (send impl new-ctx)])
             (EVP_MD_CTX_copy_ex (get-field ctx other) ctx)
             other)))
    ))

;; ============================================================

(define hmac-impl%
  (class* object% (digest-impl<%>)
    (init-field digest)

    (define/public (new-ctx key)
      (let ([ctx (HMAC_CTX_new)])
        (HMAC_Init_ex ctx key (bytes-length key) (get-field md digest))
        (new hmac-ctx% (impl this) (ctx ctx))))

    (define/public (get-name) (format "HMAC-~a" (send digest get-name)))
    (define/public (get-size) (send digest get-size))

    (super-new)
    ))


(define hmac-ctx%
  (class* base-ctx% (digest-ctx<%>)
    (init-field ctx)
    (inherit-field impl)

    (define/public (update! who buf start end)
      (check-input-range who buf start end)
      (HMAC_Update ctx (ptr-add buf start) end))

    (define/public (final! who buf start end)
      (unless ctx (error who "HMAC context is closed"))
      (let ([size (send impl get-size)])
        (check-output-range who buf start end size)
        (HMAC_Final ctx (ptr-add buf start))
        (HMAC_CTX_free ctx)
        (set! ctx #f)
        size))

    (define/public (copy) #f)

    (super-new)
    ))

;; ============================================================

(define (!digest? x) (is-a? x digest-impl%))
(define (digest? x) (is-a? x digest-ctx%))
(define (!hmac? x) (is-a? x hmac-ctx%))

(define (-digest-ctx x) (get-field ctx x))  ;; used by pkey.rkt

(define (digest-new di)
  (send di new-ctx))

(define (digest-size o)
  (cond [(is-a? o digest-impl<%>) (send o get-size)]
        [(is-a? o digest-ctx<%>) (digest-size (send o get-impl))]
        [else (raise-type-error 'digest-size "digest implementation or digest context" o)]))

(define (digest-update! x buf [start 0] [end (bytes-length buf)])
  (send x update! 'digest-update! buf start end))

(define digest-final!
  (case-lambda
    [(dg)
     (let ([bs (make-bytes (digest-size dg))])
       (digest-final! dg bs)
       bs)]
    [(dg bs)
     (digest-final! dg bs 0 (bytes-length bs))]
    [(dg bs start)
     (digest-final! dg bs start (bytes-length bs))]
    [(dg bs start end)
     (send dg final! 'digest-final! bs start end)]))

(define (digest-copy idg)
  (send idg copy 'digest-copy))

(define (digest->bytes dg)
  (digest-final! (digest-copy dg)))

(define (digest-port* di inp)
  (let ([dg (digest-new di)]
        [ibuf (make-bytes 4096)])
    (let lp ([count (read-bytes-avail! ibuf inp)])
      (cond [(eof-object? count)
             dg]
            [else
             (digest-update! dg ibuf 0 count)
             (lp (read-bytes-avail! ibuf inp))]))))

(define (digest-port type inp)
  (digest-final! (digest-port* type inp)))

(define (digest-bytes di bs)
  (let ([dg (digest-new di)])
    (digest-update! dg bs)
    (digest-final! dg)))

(define (digest* di inp)
  (cond [(bytes? inp) (digest-bytes di inp)]
        [(input-port? inp) (digest-port di inp)]
        [else (raise-type-error 'digest "bytes or input-port" inp)]))

;; ============================================================

(define (hmac-bytes di key ibs)
  (let ([evp (get-field md di)]
        [obs (make-bytes (send di get-size))])
    (HMAC evp key (bytes-length key) ibs (bytes-length ibs) obs)
    obs))

(define (hmac-port di key inp)
  (let* ([buf (make-bytes 4096)]
         [himpl (new hmac-impl% (digest di))]
         [hctx (send himpl new-ctx key)]
         [size (send himpl get-size)])
    (let loop ()
      (let ([count (read-bytes-avail! buf inp)])
        (cond [(eof-object? count)
               (send hctx final! 'hmac-port buf 0 size)
               (shrink-bytes buf size)]
              [else
               (send hctx update! 'hmac-port buf 0 count)
               (loop)])))))

(define (hmac type key inp)
  (cond [(bytes? inp) (hmac-bytes type key inp)]
        [(input-port? inp) (hmac-port type key inp)]
        [else (raise-type-error 'hmac "bytes or input-port" inp)]))

;; incremental hmac 
(define (hmac-new di key)
  (let* ([himpl (new hmac-impl% (digest di))])
    (send himpl new-ctx key)))

(define hmac-update! digest-update!)
(define hmac-final! digest-final!)

(define (generate-hmac-key t)
  (random-bytes (digest-size t)))

;; ============================================================

(define *digests* null)
(define (available-digests) *digests*)

(define (make-digest+op name proc)
  (cond [(and proc (proc))
         => (lambda (md)
              (set! *digests* (cons name *digests*))
              (let* ([di (new digest-impl% (md md) (name name))]
                     [op (lambda (inp) (digest* di inp))])
                (values di (procedure-rename op name))))]
        [else (values #f (unavailable-function name))]))

(define-syntax (define-digest stx)
  (syntax-case stx ()
    [(_ id)
     (with-syntax ([evp (format-id stx "EVP_~a" #'id)]
                   [type (format-id stx "digest:~a" #'id)])
       #'(begin
           (define-crypto evp (_fun -> _EVP_MD/null)
             #:fail (lambda () #f))
           (define-values (type id)
             (make-digest+op 'id evp))
           (put-symbols! digest.symbols type id)))]))

(define (unavailable-function who)
  (lambda x (error who "unavailable")))

(define-symbols digest.symbols
  available-digests
  !digest? digest? digest-new digest-size
  digest-update! digest-final! digest-copy digest->bytes
  (!hmac? hmac?) hmac-new hmac-update! hmac-final!
  (digest* digest) hmac)

(define-digest md5)
(define-digest ripemd160)
(define-digest dss1) ; sha1...
(define-digest sha1)
(define-digest sha224)
(define-digest sha256)
(define-digest sha384)
(define-digest sha512)

(define-provider provide-digest digest.symbols)

(provide (all-defined-out))
