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
#lang racket/base
(require ffi/unsafe
         ffi/unsafe/alloc
         racket/match
         "macros.rkt"
         "libcrypto.rkt"
         "error.rkt"
         "rand.rkt"
         "util.rkt"
         (for-syntax racket/base
                     racket/syntax
                     "stx-util.rkt"))

(define-cpointer-type _EVP_CIPHER_CTX)
(define-cpointer-type _EVP_CIPHER)

;; libcrypto < 0.9.8.d doesn't have EVP_CIPHER_CTX_new/free
(define-crypto EVP_CIPHER_CTX_free
  (_fun _EVP_CIPHER_CTX -> _void)
  #:wrap (deallocator))
(define-crypto EVP_CIPHER_CTX_new
  (_fun -> _EVP_CIPHER_CTX/null)
  #:wrap (compose (allocator EVP_CIPHER_CTX_free) (err-wrap/pointer 'EVP_CIPHER_CTX_new)))

(define-crypto EVP_CIPHER_CTX_cleanup
  (_fun _EVP_CIPHER_CTX -> _void)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_cleanup))

(define-crypto EVP_CipherInit_ex
  (_fun _EVP_CIPHER_CTX
        _EVP_CIPHER
        (_pointer = #f)
        (key : _pointer)
        (iv : _pointer)
        (enc? : _bool)
        -> _int)
  #:wrap (err-wrap/check 'EVP_CipherInit_ex))

(define-crypto EVP_CipherUpdate
  (_fun _EVP_CIPHER_CTX
        (out : _pointer)
        (olen : (_ptr o _int))
        (in : _pointer)
        (ilen : _int)
        -> (result : _int)
        -> (and (= result 1) ;; okay
                olen))
  #:wrap (err-wrap 'EVP_CipherUpdate values))

(define-crypto EVP_CipherFinal_ex
  (_fun _EVP_CIPHER_CTX
        (out : _pointer)
        (olen : (_ptr o _int))
        -> (result : _int)
        -> (and (= result 1) ;; okay
                olen))
  #:wrap (err-wrap 'EVP_CipherFinal_ex values))

(define-crypto EVP_CIPHER_CTX_set_padding
  (_fun _EVP_CIPHER_CTX
        _bool
        -> _int)
  #:wrap (err-wrap/check 'EVP_CIPHER_CTX_set_padding))

;; ----

;; ivlen: #f when no iv (0 in the cipher)
(define-struct !cipher (evp size keylen ivlen))
(define-struct cipher (type (ctx #:mutable) olen encrypt?))

(define (generate-cipher-key type)
  (let ([klen (!cipher-keylen type)]
        [ivlen (!cipher-ivlen type)])
    (values (random-bytes klen) 
            (and ivlen (pseudo-random-bytes ivlen)))))

(define (cipher-init type key iv enc? pad?)
  (let/error ([ctx (EVP_CIPHER_CTX_new) EVP_CIPHER_CTX_free])
    (EVP_CipherInit_ex ctx (!cipher-evp type) key iv enc?)
    (EVP_CIPHER_CTX_set_padding ctx pad?)
    (make-cipher type ctx (!cipher-size type) enc?)))

;; obs len >= olen + ilen
(define (cipher-update c obs ibs ilen)
  (cond [(cipher-ctx c)
         => (lambda (ctx) (EVP_CipherUpdate ctx obs ibs ilen))]
        [else (error 'cipher-update "finalized context")]))

(define (cipher-final c obs)
  (cond [(cipher-ctx c)
         => (lambda (ctx)
              (let ([olen (EVP_CipherFinal_ex ctx obs)])
                (EVP_CIPHER_CTX_free ctx)
                (set-cipher-ctx! c #f)
                olen))]
        [else (error 'cipher-final "finalized context")]))

(define (cipher-new type key iv enc? pad?)
  (unless (>= (bytes-length key) (!cipher-keylen type))
    (error 'cipher-new "bad key"))
  (when (!cipher-ivlen type)
    (unless (and iv (>= (bytes-length iv) (!cipher-ivlen type)))
      (error 'cipher-new "bad iv")))
  (cipher-init type key (if (!cipher-ivlen type) iv #f) enc? pad?))

(define (cipher-maxlen c ilen) 
  (+ ilen (cipher-olen c)))

(define (cipher-encrypt type key iv #:padding [pad? #t])
  (cipher-new type key iv #t pad?))

(define (cipher-decrypt type key iv #:padding [pad? #t])
  (cipher-new type key iv #f pad?))

;; FIXME: interface
(define cipher-update!
  (case-lambda
    [(c ibs)
     (let* ([obs (make-bytes (cipher-maxlen c (bytes-length ibs)))]
            [len (cipher-update c obs ibs (bytes-length ibs))])
       (shrink-bytes obs len))]
    [(c ibs obs)
     (check-output-range 'cipher-update! 
                         obs (cipher-maxlen c (bytes-length ibs)))
     (cipher-update c obs ibs (bytes-length ibs))]
    [(c ibs obs istart iend ostart oend)
     (check-input-range 'cipher-update! ibs istart iend)
     (check-output-range 'cipher-update! 
                         obs ostart oend (cipher-maxlen c (- iend istart)))
     (cipher-update c (ptr-add obs ostart) (ptr-add ibs istart) (- iend istart))]))

;; FIXME: interface
(define cipher-final!
  (case-lambda
    [(c)
     (let* ([bs (make-bytes (cipher-olen c))]
            [len (cipher-final c bs)])
       (shrink-bytes bs len))]
    [(c obs)
     (check-output-range 'cipher-final! obs (cipher-olen c))
     (cipher-final c obs)]
    [(c obs ostart)
     (check-output-range 'cipher-final! 
                         obs ostart (bytes-length obs) (cipher-olen c))
     (cipher-final c (ptr-add obs ostart))]
    [(c obs ostart oend)
     (check-output-range 'cipher-final! obs ostart oend (cipher-olen c))
     (cipher-final c (ptr-add obs ostart))]))

(define-syntax-rule (define-cipher-getf getf op)
  (define (getf c)
    (cond [(!cipher? c) (op c)]
          [(cipher? c) (op (cipher-type c))]
          [else (raise-type-error 'getf "cipher or cipher type" c)])))

(define-cipher-getf cipher-block-size !cipher-size)
(define-cipher-getf cipher-key-length !cipher-keylen)
(define-cipher-getf cipher-iv-length !cipher-ivlen)

(define (cipher-pipe cipher inp outp)
  (let* ([1b (cipher-block-size cipher)]
         [2b (* 2 1b)]
         [ibuf (make-bytes 1b)]
         [obuf (make-bytes 2b)])
    (let lp ([icount (read-bytes-avail! ibuf inp)])
      (if (eof-object? icount)
          (let ([ocount (cipher-final! cipher obuf)])
            (write-bytes obuf outp 0 ocount)
            (flush-output outp)
            (void))
          (let ([ocount (cipher-update! cipher ibuf obuf 0 icount 0 2b)])
            (write-bytes obuf outp 0 ocount)
            (lp (read-bytes-avail! ibuf inp)))))))

(define-syntax-rule (define/cipher-pipe id init)
  (define id
    (case-lambda
      [(algo key iv)
       (let-values ([(cipher) (init algo key iv)]
                    [(rd1 wr1) (make-pipe)]
                    [(rd2 wr2) (make-pipe)])
         (thread (lambda ()
                   (cipher-pipe cipher rd1 wr2)
                   (close-input-port rd1)
                   (close-output-port wr2)))
         (values rd2 wr1))]
      [(algo key iv inp)
       (cond [(bytes? inp) 
              (let ([outp (open-output-bytes)])
                (cipher-pipe (init algo key iv) (open-input-bytes inp) outp)
                (get-output-bytes outp))]
             [(input-port? inp)
              (let-values ([(cipher) (init algo key iv)]
                           [(rd wr) (make-pipe)])
                (thread (lambda () 
                          (cipher-pipe cipher inp wr)
                          (close-output-port wr)))
                rd)]
             [else (raise-type-error 'id "bytes or input-port" inp)])]
      [(algo key iv inp outp)
       (unless (output-port? outp)
         (raise-type-error 'id "output-port" outp))
       (cond [(bytes? inp)
              (cipher-pipe (init algo key iv) (open-input-bytes inp) outp)]
             [(input-port? inp)
              (cipher-pipe (init algo key iv) inp outp)]
             [else (raise-type-error 'id "bytes or input-port" inp)])])))

(define/cipher-pipe encrypt cipher-encrypt)
(define/cipher-pipe decrypt cipher-decrypt)

;; EVP_CIPHER: struct evp_cipher_st {nid block_size key_len iv_len ...}
(define (cipher->props evp)
  (match (ptr-ref evp (_list-struct _int _int _int _int))
    [(list _ size keylen ivlen)
     (values size keylen (and (> ivlen 0) ivlen))]))

(define *ciphers* null)
(define (available-ciphers) *ciphers*)

(define-for-syntax cipher-modes '(ecb cbc cfb ofb))
(define-for-syntax default-cipher-mode 'cbc)

(define-syntax (define-cipher stx)
  (define (unhyphen what) 
    (regexp-replace* "-" (/string what) "_"))

  (define (make-cipher mode)
    (with-syntax ([evp (format-id stx "EVP_~a" (unhyphen mode))]
                  [cipher (format-id stx "cipher:~a" mode)])
      #'(begin
          (define-crypto evp (_fun -> _EVP_CIPHER/null)
            #:fail (lambda () #f))
          (define cipher
            (cond [(and evp (evp))
                   => (lambda (evpp)
                        (call-with-values (lambda () (cipher->props evpp))
                          (lambda (size keylen ivlen)
                            (make-!cipher evpp size keylen ivlen))))]
                  [else #f]))
          (put-symbols! cipher.symbols cipher))))

  (define (make-def name)
    (with-syntax ([cipher (format-id stx "cipher:~a" name)]
                  [alias (format-id stx "cipher:~a-~a" name default-cipher-mode)])
      (let ((modes (for/list ((m cipher-modes)) (make-symbol name "-" m))))
        (with-syntax (((def ...) (map make-cipher modes)))
          #`(begin
              def ...
              (define cipher
                (begin (when alias (set! *ciphers* (cons (quote #,name) *ciphers*)))
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
