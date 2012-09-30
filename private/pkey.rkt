;; mzcrypto: libcrypto bindings for PLT-scheme
;; public key crypto
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
         "util.rkt"
         "digest.rkt"
         "cipher.rkt"
         "bn.rkt")

(define-cpointer-type _EVP_PKEY)
(define-cpointer-type _RSA)
(define-cpointer-type _DSA)

(define-crypto EVP_PKEY_free
  (_fun _EVP_PKEY -> _void)
  #:wrap (deallocator))

(define-crypto EVP_PKEY_new
  (_fun -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'EVP_PKEY_new)))

(define-crypto RSA_free
  (_fun _RSA -> _void)
  #:wrap (deallocator))
(define-crypto RSA_new
  (_fun -> _RSA)
  #:wrap (compose (allocator RSA_free) (err-wrap/pointer 'RSA_new)))

(define-crypto DSA_free
  (_fun _DSA -> _void)
  #:wrap (deallocator))
(define-crypto DSA_new
  (_fun -> _DSA)
  #:wrap (compose (allocator DSA_free) (err-wrap/pointer 'DSA_new)))

(define-crypto EVP_PKEY_type
  (_fun _int -> _int)
  #:wrap (err-wrap 'EVP_PKEY_type positive?))

(define-crypto EVP_PKEY_size
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_size positive?))

(define-crypto EVP_PKEY_bits
  (_fun _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_bits positive?))

(define-crypto EVP_PKEY_assign
  (_fun _EVP_PKEY (type : _int) (key : _pointer) -> _int)
  #:wrap (err-wrap/check 'EVP_PKEY_assign))

(define-crypto EVP_PKEY_set1_RSA
  (_fun _EVP_PKEY _RSA -> _int)
  #:wrap (err-wrap/check 'EVP_PKEY_set1_RSA))

(define-crypto EVP_PKEY_set1_DSA
  (_fun _EVP_PKEY _RSA -> _int)
  #:wrap (err-wrap/check 'EVP_PKEY_set1_DSA))

(define-crypto EVP_SignFinal
  (_fun _EVP_MD_CTX
        (sig : _pointer)
        (count : (_ptr o _uint))
        _EVP_PKEY
        -> (result : _int)
        -> (and (= result 1) count))
  #:wrap (err-wrap 'EVP_SignFinal values))

(define-crypto EVP_VerifyFinal
  (_fun _EVP_MD_CTX (buf : _pointer) (len : _uint) _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_VerifyFinal
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_cmp
  (_fun _EVP_PKEY _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_cmp
                   (lambda (r) (member r '(0 1)))
                   (lambda (r) (case r ((0) #f) ((1) #t)))))

(define-crypto EVP_PKEY_encrypt
  (_fun _pointer _pointer _int _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_encrypt exact-nonnegative-integer?))

(define-crypto EVP_PKEY_decrypt
  (_fun _pointer _pointer _int _EVP_PKEY -> _int)
  #:wrap (err-wrap 'EVP_PKEY_decrypt exact-nonnegative-integer?))

(define-crypto RSA_generate_key_ex
  (_fun _RSA _int _BIGNUM (_pointer = #f) -> _int)
  #:wrap (err-wrap/check 'RSA_generate_key_ex))

(define-crypto DSA_generate_parameters_ex
  (_fun _DSA _int
        (_pointer = #f) (_int = 0) (_pointer = #f) (_pointer = #f) (_pointer = #f)
        -> _int)
  #:wrap (err-wrap/check 'DSA_generate_parameters_ex))

(define-crypto DSA_generate_key
  (_fun _DSA -> _int)
  #:wrap (err-wrap/check 'DSA_generate_key))

(define-crypto d2i_PublicKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PublicKey)))

(define-crypto d2i_PrivateKey
  (_fun _int (_pointer = #f) (_ptr i _pointer) _long -> _EVP_PKEY/null)
  #:wrap (compose (allocator EVP_PKEY_free) (err-wrap/pointer 'd2i_PrivateKey)))

(define-crypto i2d_PublicKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PublicKey positive?))

(define-crypto i2d_PrivateKey
  (_fun _EVP_PKEY (_ptr i _pointer) -> _int)
  #:wrap (err-wrap 'i2d_PrivateKey positive?))

(define-values (i2d_PublicKey-length i2d_PrivateKey-length)
  (let ()
    (define-crypto i2d_PublicKey (_fun _EVP_PKEY (_pointer = #f) -> _int)
      #:wrap (err-wrap 'i2d_PublicKey-length positive?))
    (define-crypto i2d_PrivateKey (_fun _EVP_PKEY (_pointer = #f) -> _int)
      #:wrap (err-wrap 'i2d_PrivateKey-length positive?))
    values i2d_PublicKey i2d_PrivateKey))


(define-struct !pkey (type keygen))
(define-struct pkey (type evp private?))

(define (pkey-size pk)
  (EVP_PKEY_size (pkey-evp pk)))
  
(define (pkey-bits pk)
  (EVP_PKEY_bits (pkey-evp pk)))

(define (pkey=? k1 . klst)
  (let ((evp (pkey-evp k1)))
    (let lp ((lst klst))
      (cond
       ((null? lst) #t)
       ((EVP_PKEY_cmp evp (pkey-evp (car lst))) (lp (cdr lst)))
       (else #f)))))

(define (read-pkey type public? bs)
  (let* ((d2i (if public? d2i_PublicKey d2i_PrivateKey))
         (evp (d2i (!pkey-type type) bs (bytes-length bs)))
         (pk (make-pkey type evp (not public?))))
    (register-finalizer pk (compose EVP_PKEY_free pkey-evp))
    pk))

(define (write-pkey pk public?)
  (let*-values 
      (((i2d i2d-len) 
        (if public? 
          (values i2d_PublicKey i2d_PublicKey-length)
          (values i2d_PrivateKey i2d_PrivateKey-length)))
       ((obs) (make-bytes (i2d-len (pkey-evp pk)))))
    (i2d (pkey-evp pk) obs)
    obs))

(define-rule (define-bytes->pkey id public?)
  (define (id type bs)
    (read-pkey type public? bs)))
(define-bytes->pkey bytes->private-key #f)
(define-bytes->pkey bytes->public-key #t)

(define-rule (define-pkey->bytes id public?)
  (define (id pk)
    (write-pkey pk public?)))
(define-pkey->bytes private-key->bytes #f)
(define-pkey->bytes public-key->bytes #t)

(define (pkey->public-key pk)
  (if (pkey-private? pk)
    (bytes->public-key (pkey-type pk) (public-key->bytes pk))
    pk))

;; libcrypto #defines for those are autogened...
;; EVP_PKEY: struct evp_pkey_st {type ...}
(define (pk->type evp)
  (EVP_PKEY_type (car (ptr-ref evp (_list-struct _int)))))

(define (evp->pkey evp pkt pkp)
  (EVP_PKEY_assign evp (!pkey-type pkt) pkp)
  (let ((pk (make-pkey pkt evp #t)))
    (register-finalizer pk (compose EVP_PKEY_free pkey-evp)) ; auto-frees pkp
    pk))

(define (rsa-keygen bits (exp 65537))
  (let/fini ((ep (BN_new) BN_free))
    (BN_add_word ep exp)
    (let/error ((rsap (RSA_new) RSA_free)
                (evp (EVP_PKEY_new) EVP_PKEY_free))
      (RSA_generate_key_ex rsap bits ep)
      (evp->pkey evp pkey:rsa rsap))))

(define pkey:rsa
  (with-handlers ((exn:fail? (lambda x #f)))
    (let/fini ((rsap (RSA_new) RSA_free)
               (evp (EVP_PKEY_new) EVP_PKEY_free))
      (EVP_PKEY_set1_RSA evp rsap)
      (make-!pkey (pk->type evp) rsa-keygen))))

(define (dsa-keygen bits)
  (let/error ((dsap (DSA_new) DSA_free)
              (evp (EVP_PKEY_new) EVP_PKEY_free))
    (DSA_generate_parameters_ex dsap bits)
    (DSA_generate_key dsap)
    (evp->pkey evp pkey:dsa dsap)))

(define pkey:dsa
  (with-handlers ((exn:fail? (lambda x #f)))
    (let/fini ((dsap (DSA_new) DSA_free)
               (evp (EVP_PKEY_new) EVP_PKEY_free))
      (EVP_PKEY_set1_DSA evp dsap)
      (make-!pkey (pk->type evp) dsa-keygen))))

(define (generate-pkey type bits . args)
  (apply (!pkey-keygen type) bits args))

(define (pkey-sign dg pk bs)
  (unless (pkey-private? pk)
    (mismatch-error 'sign "not a private key"))
  (cond
   ((digest-ctx dg) => (lambda (ctx) (EVP_SignFinal ctx bs (pkey-evp pk))))
   (else (mismatch-error 'pkey-sign "finalized context"))))

(define (pkey-verify dg pk bs len)
  (cond
   ((digest-ctx dg) => (lambda (ctx) (EVP_VerifyFinal ctx bs len (pkey-evp pk))))
   (else (error 'pkey-verify "finalized context"))))

(define* digest-sign
  ((dg pk)
   (let* ((bs (make-bytes (pkey-size pk)))
          (len (pkey-sign dg pk bs)))
     (shrink-bytes bs len)))
  ((dg pk bs)
   (check-output-range digest-sign bs (pkey-size pk))
   (pkey-sign dg pk bs))
  ((dg pk bs start)
   (check-output-range digest-sign bs start (bytes-length bs) (pkey-size pk))
   (pkey-sign dg pk (ptr-add bs start)))
  ((dg pk bs start end)
   (check-output-range digest-sign bs start end (pkey-size pk))
   (pkey-sign dg pk (ptr-add bs start))))

(define* digest-verify
  ((dg pk bs)
   (pkey-verify dg pk bs (bytes-length bs)))
  ((dg pk bs start)
   (check-input-range digest-verify bs start (bytes-length bs))
   (pkey-verify dg pk (ptr-add bs start) (- (bytes-length bs) start)))
  ((dg pk bs start end)
   (check-input-range digest-verify bs start end)
   (pkey-verify dg pk (ptr-add bs start) (- end start))))

(define (sign-bytes dgt pk bs)
  (let ((dg (digest-new dgt)))
    (digest-update! dg bs)
    (digest-sign dg pk)))

(define (verify-bytes dgt pk sigbs bs)
  (let ((dg (digest-new dgt)))
    (digest-update! dg bs)
    (digest-verify dg pk sigbs)))

(define (sign-port dgt pk inp)
  (digest-sign (digest-port* dgt inp) pk))

(define (verify-port dgt pk sigbs inp)
  (digest-verify (digest-port* dgt inp) pk sigbs))

(define (sign pk dgt inp)
  (cond 
   ((bytes? inp) (sign-bytes dgt pk inp))
   ((input-port? inp) (sign-port dgt pk inp))
   (else (raise-type-error 'sign "bytes or input-port" inp))))

(define (verify pk dgt sigbs inp)
  (cond 
   ((bytes? inp) (verify-bytes dgt pk sigbs inp))
   ((input-port? inp) (verify-port dgt pk sigbs inp))
   (else (raise-type-error 'verify "bytes or input-port" inp))))

(define-rule (define-pkey-crypt crypt op evp-op public?)
  (begin
    (define (op pk ibs ilen)
      (unless (or public? (pkey-private? pk))
        (mismatch-error 'crypt "not a private key"))
      (let* ((obs (make-bytes (pkey-size pk)))
             (olen (evp-op obs ibs ilen (pkey-evp pk))))
        (shrink-bytes obs olen)))
    (define* crypt
      ((pk ibs)
       (check-input-range crypt ibs (pkey-size pk))
       (op pk ibs (bytes-length ibs)))
      ((pk ibs istart)
       (check-input-range crypt ibs istart (bytes-length ibs) (pkey-size pk))
       (op pk (ptr-add ibs istart) (- (bytes-length ibs) istart)))
      ((pk ibs istart iend)
       (check-input-range crypt ibs istart iend (pkey-size pk))
       (op pk (ptr-add ibs istart) (- iend istart))))))

(define-pkey-crypt encrypt/pkey pkey-encrypt EVP_PKEY_encrypt #t)
(define-pkey-crypt decrypt/pkey pkey-decrypt EVP_PKEY_decrypt #f)

;; sk: sealed key
(define (encrypt/envelope pk cipher . cargs)
  (let*-values (((k iv) (generate-cipher-key cipher))
                ((sk) (encrypt/pkey pk k)))
    (call/values
      (lambda () (apply encrypt cipher k iv cargs))
      (lambda cvals (apply values sk iv cvals)))))

(define (decrypt/envelope pk cipher sk iv  . cargs)
  (apply decrypt cipher (decrypt/pkey pk sk) iv cargs))

;; XXX As of openssl-0.9.8 pkeys can only be used with certain types of
;;     digests.
;;     openssl-0.9.9 is supposed to remove the restriction for digest types
(define pkey:rsa:digests 
  (filter values
    (list digest:ripemd160 
          digest:sha1 digest:sha224 digest:sha256 digest:sha384 digest:sha512)))
(define pkey:dsa:digests
  (filter values
    (list digest:dss1))) ; sha1 with fancy name

(define (pkey-digest? pk dgt)
  (cond
   ((!pkey? pk)
    (memq dgt
          (cond
           ((eq? pk pkey:rsa) pkey:rsa:digests)
           ((eq? pk pkey:dsa) pkey:dsa:digests)
           (else #f))))
   ((pkey? pk) (pkey-digest? (pkey-type pk) dgt))
   (else (raise-type-error 'pkey-digest? "pkey or pkey type" pk))))

;; Note: dsa is only usable with dss1 in libcrypto-0.9.8
(define-symbols pkey.symbols
  !pkey? pkey? pkey-private? pkey-size pkey-bits pkey=?
  pkey->public-key public-key->bytes bytes->public-key
  private-key->bytes bytes->private-key
  digest-sign digest-verify
  sign verify
  encrypt/pkey decrypt/pkey
  encrypt/envelope decrypt/envelope
  pkey:rsa pkey:dsa
  pkey:rsa:digests pkey:dsa:digests
  pkey-digest?)

(define-provider provide-pkey pkey.symbols)

(provide-pkey)
(provide provide-pkey
         generate-pkey)
