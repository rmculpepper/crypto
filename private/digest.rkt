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
         ffi/unsafe/alloc
         "macros.rkt"
         "libcrypto.rkt"
         "error.rkt"
         "rand.rkt"
         "util.rkt"
         (only-in racket/list last)
         (for-syntax racket/base
                     racket/syntax
                     "stx-util.rkt"))

(define-cpointer-type _EVP_MD_CTX)
(define-cpointer-type _EVP_MD)
(define-cpointer-type _HMAC_CTX)
(define EVP_MAX_MD_SIZE 64) ;; 512 bits

(define-crypto EVP_MD_CTX_destroy
  (_fun _EVP_MD_CTX -> _void)
  #:wrap (deallocator))

(define-crypto EVP_MD_CTX_create
  (_fun -> _EVP_MD_CTX/null)
  #:wrap (compose (allocator EVP_MD_CTX_destroy) (err-wrap/pointer 'EVP_MD_CTX_create)))

(define-crypto EVP_DigestInit_ex
  (_fun _EVP_MD_CTX
        _EVP_MD
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestInit_ex))

(define-crypto EVP_DigestUpdate
  (_fun _EVP_MD_CTX
        (d : _pointer)
        (cnt : _ulong)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestUpdate))

(define-crypto EVP_DigestFinal_ex
  (_fun _EVP_MD_CTX
        (out : _pointer)
        (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'EVP_DigestFinal_ex))

(define-crypto EVP_MD_CTX_copy_ex
  (_fun _EVP_MD_CTX
        _EVP_MD_CTX
        -> _int)
  #:wrap (err-wrap/check 'EVP_MD_CTX_copy_ex))

(define-crypto HMAC
  (_fun _EVP_MD
        (key : _pointer)
        (keylen : _int)
        (d : _pointer)
        (n : _int)
        (md : _pointer)
        (r : (_ptr o _uint))
        -> _void
        -> r))

;; ugh - no HMAC_CTX* maker in libcrypto
(define HMAC_CTX_free
  ((deallocator)
   (lambda (p)
     (HMAC_CTX_cleanup p)
     (free p))))
(define HMAC_CTX_new
  ((allocator HMAC_CTX_free)
   ((err-wrap/pointer 'HMAC_CTX_new)
    (lambda ()
      (let ([hmac (malloc 'raw 256)]) ;; FIXME: check size
        (cpointer-push-tag! hmac HMAC_CTX-tag)
        (HMAC_CTX_init hmac)
        hmac)))))

(define-crypto HMAC_CTX_init
  (_fun _HMAC_CTX -> _void))

(define-crypto HMAC_CTX_cleanup
  (_fun _HMAC_CTX -> _void))

(define-crypto HMAC_Init_ex
  (_fun _HMAC_CTX
        (key : _pointer)
        (keylen : _uint)
        _EVP_MD
        (_pointer = #f)
        -> _void) ;; _int since OpenSSL 1.0.0
  #| #:wrap (err-wrap/check 'HMAC_Init_ex) |#)

(define-crypto HMAC_Update
  (_fun _HMAC_CTX
        (data : _pointer)
        (len : _uint)
        -> _void) ;; _int since OpenSSL 1.0.0
  #| #:wrap (err-wrap/check 'HMAC_Update) |#)

(define-crypto HMAC_Final
  (_fun _HMAC_CTX
        (md : _pointer)
        (r : (_ptr o _int))
        -> _void ;; _int since OpenSSL 1.0.0
        -> r)
  #| #:wrap (err-wrap 'HMAC_Final values) |#)

;; ----

(define-struct !digest (evp size)) 
(define-struct digest (type (ctx #:mutable)))
(define-struct !hmac (type (ctx #:mutable)))

(define-rule (define-digest-update id update)
  (define* id
    ((x data)
     (update x data (bytes-length data)))
    ((x data start)
     (check-input-range id data start (bytes-length data))
     (update x (ptr-add data start) (- (bytes-length) start)))
    ((x data start end)
     (check-input-range id data start end)
     (update x (ptr-add data start) (- end start)))))

(define-rule (define-digest-final id final)
  (define* id
    ((dg)
     (let ((bs (make-bytes (digest-size dg))))
       (final dg bs)
       bs))
    ((dg bs)
     (check-output-range id bs (digest-size dg))
     (final dg bs)
     (digest-size dg))
    ((dg bs start)
     (check-output-range id bs start (bytes-length bs) (digest-size dg))
     (final dg (ptr-add bs start))
     (digest-size dg))
    ((dg bs start end)
     (check-output-range id bs start end (digest-size dg))
     (final dg (ptr-add bs start))
     (digest-size dg))))

(define (digest-size o)
  (cond [(!digest? o) (!digest-size o)]
        [(digest? o) (!digest-size (digest-type o))]
        [(!hmac? o) (!digest-size (!hmac-type o))]
        [else (raise-type-error 'digest-size "digest, hmac or digest algorithm" o)]))

(define (digest-new type)
  (let* ([evp (!digest-evp type)]
         [ctx (EVP_MD_CTX_create)])
    (EVP_DigestInit_ex ctx evp)
    (make-digest type ctx)))

(define (digest-update dg bs len)
  (cond [(digest-ctx dg)
         => (lambda (ctx) (EVP_DigestUpdate ctx bs len))]
        [else (error 'digest-update "finalized context")]))

(define-digest-update digest-update! digest-update)

(define (digest-final dg bs)
  (cond [(digest-ctx dg)
         => (lambda (ctx)
              (EVP_DigestFinal_ex ctx bs)
              (EVP_MD_CTX_destroy ctx)
              (set-digest-ctx! dg #f))]
        [else (error 'digest-final "finalized context")]))

(define-digest-final digest-final! digest-final)

(define (digest-copy idg)
  (cond [(digest-ctx idg)
         => (lambda (ictx)
              (let ([odg (digest-new (digest-type idg))])
                (EVP_MD_CTX_copy_ex (digest-ctx odg) ictx)
                odg))]
        [else (error 'digest-copy "finalized context")]))

(define (digest->bytes dg)
  (digest-final! (digest-copy dg)))

(define (digest-port* type inp)
  (let ([dg (digest-new type)]
        [ibuf (make-bytes 4096)])
    (let lp ([count (read-bytes-avail! ibuf inp)])
      (cond [(eof-object? count)
             dg]
            [else
             (digest-update! dg ibuf 0 count)
             (lp (read-bytes-avail! ibuf inp))]))))

(define (digest-port type inp)
  (digest-final! (digest-port* type inp)))

(define (digest-bytes type bs)
  (let ([dg (digest-new type)])
    (digest-update! dg bs)
    (digest-final! dg)))

(define (digest* type inp)
  (cond [(bytes? inp) (digest-bytes type inp)]
        [(input-port? inp) (digest-port type inp)]
        [else (raise-type-error 'digest "bytes or input-port" inp)]))

(define (hmac-bytes type kbs ibs)
  (let ([evp (!digest-evp type)]
        [obs (make-bytes (!digest-size type))])
    (HMAC evp kbs (bytes-length kbs) ibs (bytes-length ibs) obs)
    obs))

(define (hmac-port type k inp)
  (let ([evp (!digest-evp type)]
        [buf (make-bytes 4096)])
    (let/fini ([ctx (HMAC_CTX_new) HMAC_CTX_cleanup])
      (HMAC_Init_ex ctx k (bytes-length k) evp)
      (let lp ([count (read-bytes-avail! buf inp)])
        (cond [(eof-object? count)
               (HMAC_Final ctx buf) 
               (shrink-bytes buf (digest-size type))]
              [else
               (HMAC_Update ctx buf count)
               (lp (read-bytes-avail! buf inp))])))))

(define (hmac type key inp)
  (cond [(bytes? inp) (hmac-bytes type key inp)]
        [(input-port? inp) (hmac-port type key inp)]
        [else (raise-type-error 'hmac "bytes or input-port" inp)]))

;; incremental hmac 
(define (hmac-new type k)
  (let ([ctx (HMAC_CTX_new)])
    (HMAC_Init_ex ctx k (bytes-length k) (!digest-evp type))
    (make-!hmac type ctx)))

(define (hmac-update hx bs len)
  (cond [(!hmac-ctx hx)
         => (lambda (ctx) (HMAC_Update ctx bs len))]
        [else (error 'hmac-update "finalized context")]))

(define-digest-update hmac-update! hmac-update)

(define (hmac-final hx bs)
  (cond [(!hmac-ctx hx)
         => (lambda (ctx) (HMAC_Final ctx bs) (set-!hmac-ctx! hx #f))]
        [else (error 'hmac-update "finalized context")]))

(define-digest-final hmac-final! hmac-final)

(define (generate-hmac-key t)
  (random-bytes (digest-size t)))

(define (md->size evp)
  (last (ptr-ref evp (_list-struct _int _int _int))))

(define *digests* null)
(define (available-digests) *digests*)

(define-syntax (define-digest stx)
  (syntax-case stx ()
    [(_ id)
     (with-syntax ([evp (format-id stx "EVP_~a" #'id)]
                   [type (format-id stx "digest:~a" #'id)])
       #'(begin
           (define-crypto evp (_fun -> _EVP_MD/null)
             #:wrap (err-wrap/pointer 'evp))
           (define-values (type id)
             (cond [(ffi-available? evp)
                    (let ([evpp (evp)])
                      (set! *digests* (cons 'id *digests*))
                      (values (make-!digest evpp (md->size evpp))
                              (lambda/name id (inp) (digest* type inp))))]
                   [else (values #f (unavailable-function 'evp))]))
           (put-symbols! digest.symbols type id)))]))

(define (unavailable-function who)
  (lambda x (error who "foreign function unavailable")))

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
