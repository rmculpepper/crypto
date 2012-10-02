#lang racket/base
(require racket/class
         racket/contract/base
         "interfaces.rkt")
(provide
 (contract-out
  [pkey-impl?
   (-> any/c boolean?)]
  [pkey-ctx?
   (-> any/c boolean?)]
  [pkey-private?
   (-> pkey-ctx? boolean?)]
  [pkey-size
   (-> pkey-ctx? nat?)]
  [pkey-bits
   (-> pkey-ctx? nat?)]
  [pkey=?
   (->* (pkey-ctx?) () #:rest (listof pkey-ctx?) boolean?)]
  [pkey->public-key
   (-> pkey-ctx? pkey-ctx?)]
  [public-key->bytes
   (-> pkey-ctx? bytes?)]
  [bytes->public-key
   (-> bytes? pkey-ctx?)]
  [private-key->bytes
   (-> pkey-ctx? bytes?)]
  [bytes->private-key
   (-> bytes? pkey-ctx?)]
  [digest-sign
   (-> digest-ctx? pkey-ctx?
       bytes?)]
  [digest-sign!
   (->* (digest-ctx? pkey-ctx? bytes?) (nat? nat?)
        nat?)]
  [digest-verify
   (->* (digest-ctx? pkey-ctx? bytes?) (nat? nat?)
        boolean?)]
  [sign
   (-> pkey-ctx? digest-impl? (or/c input-port? bytes?)
       bytes?)]
  [verify
   (-> pkey-ctx? digest-impl? bytes? (or/c input-port? bytes?)
       boolean?)]
  [encrypt/pkey
   (->* (pkey-ctx? bytes?) (nat? nat?)
        bytes?)]
  [decrypt/pkey
   (->* (pkey-ctx? bytes?) (nat? nat?)
        bytes?)]
  [encrypt/envelope
   (case->
    (-> pkey-ctx? cipher-impl?
        (values key/c iv/c input-port? output-port?))
    (-> pkey-ctx? cipher-impl? (or/c input-port? bytes?)
        (values key/c iv/c input-port?))
    (-> pkey-ctx? cipher-impl? (or/c input-port? bytes?) output-port?
        (values key/c iv/c)))]
  [decrypt/envelope
   (case->
    (-> pkey-ctx? cipher-impl?
        (values key/c iv/c input-port? output-port?))
    (-> pkey-ctx? cipher-impl? (or/c input-port? bytes?)
        (values key/c iv/c input-port?))
    (-> pkey-ctx? cipher-impl? (or/c input-port? bytes?) output-port?
        (values key/c iv/c)))]
  [generate-pkey
   (->* (pkey-impl? nat?) () #:rest any/c
        pkey-ctx?)]))

(define nat? exact-nonnegative-integer?)
(define key/c bytes?)
(define iv/c (or/c bytes? #f))

;; ============================================================

(define (pkey-impl? x) (is-a? x pkey-impl<%>))
(define (pkey-ctx? x) (is-a? x pkey-ctx<%>))

(define (pkey-private? pk) (send pk is-private?))
(define (pkey-size pk) (send pk get-max-signature-size))
(define (pkey-bits pk) (send pk get-key-size/bits))

(define (pkey=? k1 . ks)
  (for/and ([k (in-list ks)])
    (send k1 equal-to-key? k)))

(define (bytes->private-key pki bs) (-read-pkey 'bytes->private-key pki #f bs))
(define (bytes->public-key pki bs)  (-read-pkey 'bytes->public-key pki #t bs))
(define (private-key->bytes pk) (-write-pkey 'private-key->bytes pk #f))
(define (public-key->bytes pk)  (-write-pkey 'public-key->bytes pk #t))

(define (-read-pkey who pki public? bs)
  (send pki read-key who public? bs 0 (bytes-length bs)))
(define (-write-pkey pk public?)
  (send pk write-key who public?))

(define (pkey->public-key pk)
  (if (pkey-private? pk)
      (bytes->public-key (send pk get-impl) (public-key->bytes pk))
      pk))

(define (generate-pkey pki bits . args)
  (send pki generate-key (cons bits args)))

;; ============================================================

(define (digest-sign dg pk)
  (let* ([est-len (pkey-size pk)]
         [buf (make-bytes est-len)]
         [len (send pk sign! 'digest-sign dg buf 0 est-len)])
    (shrink-bytes buf len)))

(define (digest-sign! dg pk buf [start 0] [end (bytes-length buf)])
  (send pk sign! 'digest-sign dg buf start end))

(define (digest-verify dg pk buf [start 0] [end (bytes-length buf)])
  (send pk verify 'digest-verify dg buf start end))

;; ============================================================

(define (sign pk dgt inp)
  (define (sign-bytes dgt pk bs)
    (let ([dg (digest-new dgt)])
      (digest-update! dg bs)
      (digest-sign dg pk)))
  (define (sign-port dgt pk inp)
    (digest-sign (digest-port* dgt inp) pk))
  (cond [(bytes? inp) (sign-bytes dgt pk inp)]
        [(input-port? inp) (sign-port dgt pk inp)]
        [else (raise-type-error 'sign "bytes or input-port" inp)]))

(define (verify pk dgt sigbs inp)
  (define (verify-bytes dgt pk sigbs bs)
    (let ([dg (digest-new dgt)])
      (digest-update! dg bs)
      (digest-verify dg pk sigbs)))
  (define (verify-port dgt pk sigbs inp)
    (digest-verify (digest-port* dgt inp) pk sigbs))
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
