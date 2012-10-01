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
         racket/class
         "../common/interfaces.rkt"
         "../common/common.rkt"
         "ffi.rkt"
         "macros.rkt"
         "util.rkt"
         "digest.rkt"
         "cipher.rkt")

(define pkey-impl%
  (class* object% (#|pkey-impl<%>|#)
    (init-field pktype
                keygen)
    (super-new)

    (define/public (read-key who public? buf start end)
      (check-input-range who buf start end)
      (let* ([d2i (if public? d2i_PublicKey d2i_PrivateKey)]
             [evp (d2i pktype (ptr-add buf start) (- end start))])
        (new pkey-ctx% (impl this) (evp evp) (private? (not public?)))))

    (define/public (generate-key args)
      (apply keygen args))

    ))

(define pkey-ctx%
  (class* base-ctx% (pkey-ctx<%>)
    (init-field evp
                private?)
    (super-new)

    (define/public (is-private?) private?)

    (define/public (get-max-signature-size) (EVP_PKEY_size evp))
    (define/public (get-key-size/bits) (EVP_PKEY_bits evp))

    (define/public (write-key who public?)
      (let* ([i2d (if public? i2d_PublicKey i2d_PrivateKey)]
             [i2d-length (if public? i2d_PublicKey-length i2d_PrivateKey-length)]
             [buf (make-bytes (i2d-length evp))])
        (i2d evp buf)
        buf))

    (define/public (equal-to-key? other)
      (and (is-a? other pkey-ctx%)
           (EVP_PKEY_cmp evp (get-field evp other))))

    ;; From headers, EVP_{Sign,Verify}{Init_ex,Update} are just macros for
    ;; EVP_Digest{Init_ex,Update}. So digest state is compatible.

    (define/public (sign! who digest-ctx buf start end)
      (unless private?
        (error who "not a private key"))
      ;; FIXME: add method to digest-ctx% instead (?)
      (unless (is-a? digest-ctx digest-ctx%)
        (error who "invalid digest context, not compatible with libcrypto"))
      (check-output-range who buf start end (get-max-signature-size))
      (let ([dctx (get-field ctx digest-ctx)])
        (unless dctx (error who "digest context is closed"))
        (EVP_SignFinal dctx (ptr-add buf start) evp)))

    (define/public (verify who digest-ctx buf start end)
      ;; FIXME: add methdo to digest-ctx% instead (?)
      (unless (is-a? digest-ctx digest-ctx%)
        (error who "invalid digest context, not compatible with libcrypto"))
      (check-input-range who buf start end)
      (let ([dctx (get-field ctx digest-ctx)])
        (unless dctx (error who "digest context is closed"))
        (EVP_VerifyFinal dctx (ptr-add buf start) (- end start) evp)))

    (define/public (encrypt/decrypt who encrypt? public? inbuf instart inend)
      (unless (or public? (is-private?))
        (error who "not a private key"))
      (check-input-range who inbuf instart inend)
      (let* ([outbuf (make-bytes (get-max-signature-size))]
             [e/d (if encrypt? EVP_PKEY_encrypt EVP_PKEY_decrypt)]
             [outlen (e/d outbuf (ptr-add inbuf instart) (- inend instart) evp)])
        (shrink-bytes outbuf outlen)))

    ))

;; ============================================================

;; ============================================================

;; (define-struct !pkey (type keygen))
;; (define-struct pkey (type evp private?))
(define (!pkey? x) (is-a? x pkey-impl%))
(define (pkey? x) (is-a? x pkey-ctx%))
(define (pkey-private? x) (send x is-private?))
(define (-pkey-type x) (send x get-impl))

(define (pkey-size pk) (send pk get-max-signature-size))
(define (pkey-bits pk) (send pk get-key-size/bits))

(define (pkey=? k1 . ks)
  (for/and ([k (in-list ks)])
    (send k1 equal-to-key? k)))

(define (read-pkey pki public? bs)
  (send pki read-key 'read-pkey public? bs 0 (bytes-length bs)))
(define (write-pkey pk public?)
  (send pk write-key 'write-pkey public?))

(define (bytes->private-key pki bs) (read-pkey pki #f bs))
(define (bytes->public-key pki bs)  (read-pkey pki #t bs))

(define (private-key->bytes pk) (write-pkey pk #f))
(define (public-key->bytes pk)  (write-pkey pk #t))

(define (pkey->public-key pk)
  (if (pkey-private? pk)
      (bytes->public-key (send pk get-impl) (public-key->bytes pk))
      pk))

(define (generate-pkey pki bits . args)
  (send pki generate-key (cons bits args)))

;; ============================================================

(define (rsa-keygen bits [exp 65537])
  (let/fini ([ep (BN_new) BN_free])
    (BN_add_word ep exp)
    (let/error ([rsap (RSA_new) RSA_free]
                [evp (EVP_PKEY_new) EVP_PKEY_free])
      (RSA_generate_key_ex rsap bits ep)
      (EVP_PKEY_set1_RSA evp rsap)
      (new pkey-ctx% (impl pkey:rsa) (evp evp) (private? #t)))))

(define (dsa-keygen bits)
  (let/error ([dsap (DSA_new) DSA_free]
              [evp (EVP_PKEY_new) EVP_PKEY_free])
    (DSA_generate_parameters_ex dsap bits)
    (DSA_generate_key dsap)
    (EVP_PKEY_set1_DSA evp dsap)
    (new pkey-ctx% (impl pkey:dsa) (evp evp) (private? #t))))

;; ============================================================

;; FIXME: get pktype constants from C headers

;; libcrypto #defines for those are autogened...
;; EVP_PKEY: struct evp_pkey_st {type ...}
(define (pk->type evp)
  (EVP_PKEY_type (car (ptr-ref evp (_list-struct _int)))))

(define pkey:rsa
  (with-handlers (#|(exn:fail? (lambda x #f))|#)
    (let ([pktype (let/fini ([rsap (RSA_new) RSA_free]
                             [evp (EVP_PKEY_new) EVP_PKEY_free])
                    (EVP_PKEY_set1_RSA evp rsap)
                    (pk->type evp))])
      (new pkey-impl% (pktype pktype) (keygen rsa-keygen)))))

(define pkey:dsa
  (with-handlers (#|(exn:fail? (lambda x #f))|#)
    (let ([pktype (let/fini ([dsap (DSA_new) DSA_free]
                             [evp (EVP_PKEY_new) EVP_PKEY_free])
                    (EVP_PKEY_set1_DSA evp dsap)
                    (pk->type evp))])
      (new pkey-impl% (pktype pktype) (keygen dsa-keygen)))))

;; ============================================================

(define digest-sign
  (case-lambda
    [(dg pk)
     (let* ([bs (make-bytes (pkey-size pk))]
            [len (digest-sign dg pk bs)])
       (shrink-bytes bs len))]
    [(dg pk buf)
     (send pk sign! 'digest-sign dg buf 0 (bytes-length buf))]
    [(dg pk buf start)
     (send pk sign! 'digest-sign dg buf start (bytes-length buf))]
    [(dg pk buf start end)
     (send pk sign! 'digest-sign dg buf start end)]))

(define (digest-verify dg pk buf [start 0] [end (bytes-length buf)])
  (send pk verify 'digest-verify dg buf start end))

;; ============================================================

(define (sign-bytes dgt pk bs)
  (let ([dg (digest-new dgt)])
    (digest-update! dg bs)
    (digest-sign dg pk)))

(define (verify-bytes dgt pk sigbs bs)
  (let ([dg (digest-new dgt)])
    (digest-update! dg bs)
    (digest-verify dg pk sigbs)))

(define (sign-port dgt pk inp)
  (digest-sign (digest-port* dgt inp) pk))

(define (verify-port dgt pk sigbs inp)
  (digest-verify (digest-port* dgt inp) pk sigbs))

(define (sign pk dgt inp)
  (cond [(bytes? inp) (sign-bytes dgt pk inp)]
        [(input-port? inp) (sign-port dgt pk inp)]
        [else (raise-type-error 'sign "bytes or input-port" inp)]))

(define (verify pk dgt sigbs inp)
  (cond [(bytes? inp) (verify-bytes dgt pk sigbs inp)]
        [(input-port? inp) (verify-port dgt pk sigbs inp)]
        [else (raise-type-error 'verify "bytes or input-port" inp)]))

;; ============================================================

(define (encrypt/pkey pk buf [start 0] [end (bytes-length buf)])
  (send pk encrypt/decrypt 'encrypt/pkey #t #t buf start end))

(define (decrypt/pkey pk buf [start 0] [end (bytes-length buf)])
  (send pk encrypt/decrypt 'encrypt/pkey #f #f buf start end))

;; ============================================================

;; sk: sealed key
(define (encrypt/envelope pk cipher . cargs)
  (let*-values ([(k iv) (generate-cipher-key cipher)]
                [(sk) (encrypt/pkey pk k)])
    (call-with-values (lambda () (apply encrypt cipher k iv cargs))
      (lambda cvals (apply values sk iv cvals)))))

(define (decrypt/envelope pk cipher sk iv  . cargs)
  (apply decrypt cipher (decrypt/pkey pk sk) iv cargs))

;; ============================================================

;; Note: dsa is only usable with dss1 in libcrypto-0.9.8
(define-symbols pkey.symbols
  !pkey? pkey? pkey-private? pkey-size pkey-bits pkey=?
  pkey->public-key public-key->bytes bytes->public-key
  private-key->bytes bytes->private-key
  digest-sign digest-verify
  sign verify
  encrypt/pkey decrypt/pkey
  encrypt/envelope decrypt/envelope
  pkey:rsa pkey:dsa)

(define-provider provide-pkey pkey.symbols)

(provide-pkey)
(provide provide-pkey
         generate-pkey
         -pkey-type)
