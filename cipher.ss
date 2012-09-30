;; mzcrypto: libcrypto bindings for PLT-scheme
;; symmetric ciphers
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
         scheme/match
         "macros.ss"
         "libcrypto.ss"
         "error.ss"
         "rand.ss"
         "util.ss"
         (for-syntax scheme/base "stx-util.ss"))

(unsafe!)

;; libcrypto < 0.9.8.d doesn't have EVP_CIPHER_CTX_new/free
(define-values (EVP_CIPHER_CTX_new EVP_CIPHER_CTX_free)
  (if (ffi-available? EVP_CIPHER_CTX_new)
    (values
      (lambda/ffi (EVP_CIPHER_CTX_new) -> _pointer : pointer/error)
      (lambda/ffi (EVP_CIPHER_CTX_free _pointer)))
    (values 
      (lambda () (make-bytes 192)) ; a little bigger than needed
      (lambda/ffi (EVP_CIPHER_CTX_cleanup _pointer) -> _int : void))))

(define/ffi (EVP_CipherInit_ex _pointer _pointer (_pointer = #f)
                               _pointer _pointer _bool) 
  -> _int : check-error)
(define/ffi (EVP_CipherUpdate _pointer _pointer 
                              (olen : (_ptr o _int)) _pointer _int)
  -> _int : (lambda (f r) (check-error f r) olen))
(define/ffi (EVP_CipherFinal_ex _pointer _pointer (olen : (_ptr o _int)))
  -> _int : (lambda (f r) (check-error f r) olen))
(define/ffi (EVP_CIPHER_CTX_set_padding _pointer _bool) 
  -> _int : check-error)

;; ivlen: #f when no iv (0 in the cipher)
(define-struct !cipher (evp size keylen ivlen))
(define-struct cipher (type (ctx #:mutable) olen encrypt?))

(define (generate-cipher-key type)
  (let ((klen (!cipher-keylen type))
        (ivlen (!cipher-ivlen type)))
    (values (random-bytes klen) 
            (and ivlen (pseudo-random-bytes ivlen)))))

(define (cipher-init type key iv enc? pad?)
  (let/error ((ctx (EVP_CIPHER_CTX_new) EVP_CIPHER_CTX_free))
    (EVP_CipherInit_ex ctx (!cipher-evp type) key iv enc?)
    (EVP_CIPHER_CTX_set_padding ctx pad?)
    (let ((c (make-cipher type ctx (!cipher-size type) enc?)))
      (register-finalizer c
        (lambda (o) (cond ((cipher-ctx o) => EVP_CIPHER_CTX_free))))
      c)))

;; obs len >= olen + ilen
(define (cipher-update c obs ibs ilen)
  (cond
   ((cipher-ctx c) => (lambda (ctx) (EVP_CipherUpdate ctx obs ibs ilen)))
   (else (mismatch-error 'cipher-update "finalized context"))))

(define (cipher-final c obs)
  (cond
   ((cipher-ctx c) =>
    (lambda (ctx)
      (let ((olen (EVP_CipherFinal_ex ctx obs)))
        (EVP_CIPHER_CTX_free ctx)
        (set-cipher-ctx! c #f)
        olen)))
   (else (mismatch-error 'cipher-final "finalized context"))))

(define (cipher-new type key iv enc? pad?)
  (unless (>= (bytes-length key) (!cipher-keylen type))
    (mismatch-error 'cipher-new "bad key"))
  (when (!cipher-ivlen type)
    (unless (and iv (>= (bytes-length iv) (!cipher-ivlen type)))
      (mismatch-error 'cipher-new "bad iv")))
  (cipher-init type key (if (!cipher-ivlen type) iv #f) enc? pad?))

(define-rule (cipher-maxlen c ilen) 
  (+ ilen (cipher-olen c)))

(define (cipher-encrypt type key iv #:padding (pad? #t))
  (cipher-new type key iv #t pad?))

(define (cipher-decrypt type key iv #:padding (pad? #t))
  (cipher-new type key iv #f pad?))

(define* cipher-update!
  ((c ibs)
   (let* ((obs (make-bytes (cipher-maxlen c (bytes-length ibs))))
          (len (cipher-update c obs ibs (bytes-length ibs))))
     (shrink-bytes obs len)))
  ((c ibs obs)
   (check-output-range cipher-update! 
     obs (cipher-maxlen c (bytes-length ibs)))
   (cipher-update c obs ibs (bytes-length ibs)))
  ((c ibs obs istart iend ostart oend)
   (check-input-range cipher-update! ibs istart iend)
   (check-output-range cipher-update! 
     obs ostart oend (cipher-maxlen c (- iend istart)))
   (cipher-update c (ptr-add obs ostart) (ptr-add ibs istart) (- iend istart))))

(define* cipher-final!
  ((c)
   (let* ((bs (make-bytes (cipher-olen c)))
          (len (cipher-final c bs)))
     (shrink-bytes bs len)))
  ((c obs)
   (check-output-range cipher-final! obs (cipher-olen c))
   (cipher-final c obs))
  ((c obs ostart)
   (check-output-range cipher-final! 
     obs ostart (bytes-length obs) (cipher-olen c))
   (cipher-final c (ptr-add obs ostart)))
  ((c obs ostart oend)
   (check-output-range cipher-final! obs ostart oend (cipher-olen c))
   (cipher-final c (ptr-add obs ostart))))

(define-rule (define-cipher-getf getf op)
  (define (getf c)
    (cond
     ((!cipher? c) (op c))
     ((cipher? c) (op (cipher-type c)))
     (else (raise-type-error 'getf "cipher or cipher type" c)))))

(define-cipher-getf cipher-block-size !cipher-size)
(define-cipher-getf cipher-key-length !cipher-keylen)
(define-cipher-getf cipher-iv-length !cipher-ivlen)

(define (cipher-pipe cipher inp outp)
  (let* ((1b (cipher-block-size cipher))
         (2b (* 2 1b))
         (ibuf (make-bytes 1b))
         (obuf (make-bytes 2b)))
    (let lp ((icount (read-bytes-avail! ibuf inp)))
      (if (eof-object? icount)
        (let ((ocount (cipher-final! cipher obuf)))
          (write-bytes obuf outp 0 ocount)
          (flush-output outp)
          (void))
        (let ((ocount (cipher-update! cipher ibuf obuf 0 icount 0 2b)))
          (write-bytes obuf outp 0 ocount)
          (lp (read-bytes-avail! ibuf inp)))))))

(define-rule (define/cipher-pipe id init)
  (define* id
    ((algo key iv)
     (let-values (((cipher) (init algo key iv))
                  ((rd1 wr1) (make-pipe))
                  ((rd2 wr2) (make-pipe)))
       (thread (lambda ()
                 (cipher-pipe cipher rd1 wr2)
                 (close-input-port rd1)
                 (close-output-port wr2)))
       (values rd2 wr1)))
    ((algo key iv inp)
     (cond 
      ((bytes? inp) 
       (let ((outp (open-output-bytes)))
         (cipher-pipe (init algo key iv) (open-input-bytes inp) outp)
         (get-output-bytes outp)))
      ((input-port? inp)
       (let-values (((cipher) (init algo key iv))
                    ((rd wr) (make-pipe)))
         (thread (lambda () 
                   (cipher-pipe cipher inp wr)
                   (close-output-port wr)))
         rd))
      (else (raise-type-error 'id "bytes or input-port" inp))))
    ((algo key iv inp outp)
     (unless (output-port? outp)
       (raise-type-error 'id "output-port" outp))
     (cond 
      ((bytes? inp)
       (cipher-pipe (init algo key iv) (open-input-bytes inp) outp))
      ((input-port? inp)
       (cipher-pipe (init algo key iv) inp outp))
      (else (raise-type-error 'id "bytes or input-port" inp))))))

(define/cipher-pipe encrypt cipher-encrypt)
(define/cipher-pipe decrypt cipher-decrypt)

;; EVP_CIPHER: struct evp_cipher_st {nid block_size key_len iv_len ...}
(define (cipher->props evp)
  (match (ptr-ref evp (_list-struct _int _int _int _int))
    ((list _ size keylen ivlen)
     (values size keylen (and (> ivlen 0) ivlen)))))

(define *ciphers* null)
(define (available-ciphers) *ciphers*)

(define-for-syntax cipher-modes '(ecb cbc cfb ofb))
(define-for-syntax default-cipher-mode 'cbc)

(define-syntax (define-cipher stx)
  (define (unhyphen what) 
    (regexp-replace* "-" (/string what) "_"))

  (define (make-cipher mode)
    (with-syntax
        ((evp (/identifier stx "EVP_" (unhyphen mode)))
         (cipher (/identifier stx "cipher:" mode)))
      #'(begin
          (define cipher
            (if (ffi-available? evp)
              (let ((evpp ((lambda/ffi (evp) -> _pointer))))
                (call/values 
                  (lambda () (cipher->props evpp))
                  (lambda (size keylen ivlen)
                    (make-!cipher evpp size keylen ivlen))))
              #f))
          (put-symbols! cipher.symbols cipher))))
  
  (define (make-def name)
    (with-syntax 
        ((cipher (/identifier stx "cipher:" name))
         (alias (/identifier stx "cipher:" name "-" default-cipher-mode)))
      (let ((modes (for/list ((m cipher-modes)) (make-symbol name "-" m))))
        (with-syntax (((def ...) (map make-cipher modes)))
          #`(begin
              def ...
              (define cipher
                (begin (when alias (push! *ciphers* (quote #,name)))
                       alias))
              (put-symbols! cipher.symbols cipher))))))
  
  (syntax-case stx ()
    ((_ c) (make-def (syntax-e #'c)))
    ((_ c (klen ...))
     (with-syntax (((def ...) 
                    (for/list ((k (syntax->list #'(klen ...))))
                      (make-def (make-symbol #'c "-" k)))))
       #'(begin def ...)))))

(define-symbols cipher.symbols
  available-ciphers 
  !cipher?
  cipher?
  cipher-encrypt?
  cipher-block-size cipher-key-length cipher-iv-length
  cipher-encrypt cipher-decrypt cipher-update! cipher-final!
  encrypt decrypt)

(define-cipher des)
(define-cipher des-ede)
(define-cipher des-ede3)
(define-cipher idea)
(define-cipher bf)
(define-cipher cast5)
(define-cipher aes (128 192 256))
(define-cipher camellia (128 192 256))

(define-provider provide-cipher cipher.symbols)

(provide-cipher)
(provide provide-cipher generate-cipher-key)
