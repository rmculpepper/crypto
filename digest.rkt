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
#lang scheme/base

(require scheme/foreign
         "macros.rkt"
         "libcrypto.rkt"
         "error.rkt"
         "rand.rkt"
         "util.rkt"
         (only-in scheme/list last)
         (for-syntax scheme/base "stx-util.rkt")
         )
(unsafe!)

(define/ffi (EVP_MD_CTX_create) -> _pointer : pointer/error)
(define/ffi (EVP_DigestInit_ex _pointer _pointer (_pointer = #f))
  -> _int : check-error)
(define/ffi (EVP_DigestUpdate _pointer _pointer _ulong)
  -> _int : check-error)
(define/ffi (EVP_DigestFinal_ex _pointer _pointer (_pointer = #f))
  -> _int : check-error)
(define/ffi (EVP_MD_CTX_copy_ex _pointer _pointer)
  -> _int : check-error)
(define/ffi (EVP_MD_CTX_destroy _pointer))
(define/ffi (HMAC _pointer _pointer _int _pointer _int 
                  _pointer (r : (_ptr o _uint)))
  -> _pointer : (lambda x r))
(define/ffi (HMAC_CTX_init _pointer))
(define/ffi (HMAC_CTX_cleanup _pointer))
(define/ffi (HMAC_Init_ex _pointer _pointer _uint _pointer (_pointer = #f)))
(define/ffi (HMAC_Update _pointer _pointer _uint))
(define/ffi (HMAC_Final _pointer _pointer (r : (_ptr o _int)))
  -> _void : (lambda x r))

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
  (cond
   ((!digest? o) (!digest-size o))
   ((digest? o) (!digest-size (digest-type o)))
   ((!hmac? o) (!digest-size (!hmac-type o)))
   (else (raise-type-error 'digest-size "digest, hmac or digest algorithm" o))))

(define (digest-new type)
  (let* ((evp (!digest-evp type))
         (dg (make-digest type (EVP_MD_CTX_create))))
    (register-finalizer dg
      (lambda (o) (cond ((digest-ctx o) => EVP_MD_CTX_destroy))))
    (EVP_DigestInit_ex (digest-ctx dg) evp)
    dg))

(define (digest-update dg bs len)
  (cond
   ((digest-ctx dg) => (lambda (ctx) (EVP_DigestUpdate ctx bs len)))
   (else (mismatch-error 'digest-update "finalized context"))))

(define-digest-update digest-update! digest-update)

(define (digest-final dg bs)
  (cond
   ((digest-ctx dg) =>
    (lambda (ctx)
      (EVP_DigestFinal_ex ctx bs)
      (EVP_MD_CTX_destroy ctx)
      (set-digest-ctx! dg #f)))
   (else (mismatch-error 'digest-final "finalized context"))))

(define-digest-final digest-final! digest-final)

(define (digest-copy idg)
  (cond
   ((digest-ctx idg) =>
    (lambda (ictx)
      (let ((odg (digest-new (digest-type idg))))
        (EVP_MD_CTX_copy_ex (digest-ctx odg) ictx)
        odg)))
   (else (mismatch-error 'digest-copy "finalized context"))))

(define (digest->bytes dg)
  (digest-final! (digest-copy dg)))

(define (digest-port* type inp)
  (let ((dg (digest-new type))
        (ibuf (make-bytes 4096)))
    (let lp ((count (read-bytes-avail! ibuf inp)))
      (if (eof-object? count)
        dg 
        (begin
          (digest-update! dg ibuf 0 count)
          (lp (read-bytes-avail! ibuf inp)))))))

(define (digest-port type inp)
  (digest-final! (digest-port* type inp)))

(define (digest-bytes type bs)
  (let ((dg (digest-new type)))
    (digest-update! dg bs)
    (digest-final! dg)))

(define (digest* type inp)
  (cond
   ((bytes? inp) (digest-bytes type inp))
   ((input-port? inp) (digest-port type inp))
   (else (raise-type-error 'digest "bytes or input-port" inp))))

(define (hmac-bytes type kbs ibs)
  (let ((evp (!digest-evp type))
        (obs (make-bytes (!digest-size type))))
    (HMAC evp kbs (bytes-length kbs) ibs (bytes-length ibs) obs)
    obs))

(define (make-hmac-ctx)
  (let ((ctx (make-bytes 256))) ; ugh - no HMAC_CTX* maker in libcrypto
    (HMAC_CTX_init ctx)
    ctx))

(define (hmac-port type k inp)
  (let ((evp (!digest-evp type))
        (buf (make-bytes 4096)))
    (let/fini ((ctx (make-hmac-ctx) HMAC_CTX_cleanup))
      (HMAC_Init_ex ctx k (bytes-length k) evp)
      (let lp ((count (read-bytes-avail! buf inp)))
        (if (eof-object? count)
          (begin 
            (HMAC_Final ctx buf) 
            (shrink-bytes buf (digest-size type)))
          (begin 
            (HMAC_Update ctx buf count)
            (lp (read-bytes-avail! buf inp))))))))

(define (hmac type key inp)
  (cond
   ((bytes? inp) (hmac-bytes type key inp))
   ((input-port? inp) (hmac-port type key inp))
   (else (raise-type-error 'hmac "bytes or input-port" inp))))

;; incremental hmac 
(define (hmac-new type k)
  (let ((ctx (make-hmac-ctx)))
    (HMAC_Init_ex ctx k (bytes-length k) (!digest-evp type))
    (register-finalizer ctx HMAC_CTX_cleanup)
    (make-!hmac type ctx)))

(define (hmac-update hx bs len)
  (cond
   ((!hmac-ctx hx) => (lambda (ctx) (HMAC_Update ctx bs len)))
   (else (mismatch-error 'hmac-update "finalized context"))))

(define-digest-update hmac-update! hmac-update)

(define (hmac-final hx bs)
  (cond
   ((!hmac-ctx hx) => (lambda (ctx) (HMAC_Final ctx bs) (set-!hmac-ctx! hx #f)))
   (else (mismatch-error 'hmac-update "finalized context"))))

(define-digest-final hmac-final! hmac-final)

(define (generate-hmac-key t)
  (random-bytes (digest-size t)))

(define (md->size evp)
  (last (ptr-ref evp (_list-struct _int _int _int))))

(define *digests* null)
(define (available-digests) *digests*)

(define-syntax (define-digest stx)
  (syntax-case stx ()
    ((_ id)
     (with-syntax
         ((evp (/identifier stx "EVP_" #'id))
          (type (/identifier stx "digest:" #'id)))
       #'(begin
           (define-values (type id)
             (if (ffi-available? evp)
               (let ((evpp ((lambda/ffi (evp) -> _pointer : pointer/error))))
                 (push! *digests* 'id)
                 (values (make-!digest evpp (md->size evpp))
                         (lambda/name id (inp) (digest* type inp))))
               (values #f (unavailable-function evp))))
           (put-symbols! digest.symbols type id))))))

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

(provide-digest)
(provide provide-digest
         (struct-out !digest)
         (struct-out !hmac)
         digest*
         digest-ctx
         digest-port
         digest-port*
         generate-hmac-key
         )