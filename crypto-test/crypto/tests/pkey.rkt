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
         racket/port
         rackunit
         crypto
         crypto/private/common/util
         "digest.rkt"
         "util.rkt")
(provide test-pk)

;; Sign/verify
;;  - privkey signs, privkey verifies, pubkey verifies, privkey2 doesn't verify

;; Encrypt/decrypt
;;  - privkey encrypts, privkey decrypts
;;  - pubkey encrypts, privkey decrypts
;;  - privkey encrypts, privkey2 doesn't decrypt

;; Key agreement
;;  - privkey1+pubkey2 derives same key as privkey2+pubkey11

(define (readkey sexpr factory)
  (with-handlers ([exn:fail? (lambda (e) #f)])
    (datum->pk-key (caddr sexpr) (car sexpr) factory)))

(define (test-pk factory factory-name [pub-factories null])
  (for ([key-sexpr private-keys])
    (define key (readkey key-sexpr factory))
    (define pubkey (and key (pk-key->public-only-key key)))
    (unless key
      (when #t
        (eprintf "-  cannot read ~s (~s)\n" (cadr key-sexpr) factory-name)))
    (when key
      (when #t
        (eprintf "+  testing ~s (~s)\n" (cadr key-sexpr) factory-name))
      (test-case (format "~a ~a ~a" factory-name (car key-sexpr) (cadr key-sexpr))
        ;; Can convert to pubkey, can serialize and deserialize
        (check-pred private-key? key)
        (check-pred public-only-key? pubkey)
        (check public-key=? key pubkey)
        (test-pk-key key pubkey))
      (define pubkey-der (pk-key->datum pubkey 'SubjectPublicKeyInfo))
      (for ([pub-factory (remove factory pub-factories)])
        (define pubkey*
          (with-handlers ([exn:fail? (lambda (e) #f)])
            (datum->pk-key pubkey-der 'SubjectPublicKeyInfo pub-factory)))
        (unless pubkey*
          (when #t
            (eprintf " - cannot read public key for ~s (~s)\n" (cadr key-sexpr) pub-factory)))
        (when pubkey*
          (when #t
            (eprintf " + cross-testing with ~s\n" pub-factory))
          ;; (check public-key=? pubkey pubkey*) ;; FIXME?
          (test-case (format "~a => ~a, ~a ~a" factory-name pub-factory
                             (car key-sexpr) (cadr key-sexpr))
            (test-pk-key key pubkey*)))))))

(define (test-pk-key key pubkey)
  (when (pk-can-sign? key)
    (test-pk-sign key pubkey))
  (when (pk-can-encrypt? key)
    (test-pk-encrypt key pubkey))
  (when (pk-can-key-agree? key)
    (test-pk-key-agree key pubkey)))

(define msg #"I am the walrus.")
(define badmsg #"I am the egg nog.")

(define (test-pk-sign key pubkey)
  (define rsa? (eq? (send (send key get-impl) get-spec) 'rsa))
  (for* ([pad (if rsa? '(pkcs1-v1.5 pss) '(#f))]
         [di '(sha1 sha256)])
    (define di* (get-digest di (get-factory key)))
    (define sig1 (pk-sign-digest key di (digest di* msg) #:pad pad))
    (define sig2 (digest/sign key di msg #:pad pad))

    (check-true (pk-verify-digest key di (digest di* msg) sig1 #:pad pad) "pvd key sig1")
    (check-true (pk-verify-digest key di (digest di* msg) sig2 #:pad pad) "pvd key sig2")
    (check-true (pk-verify-digest pubkey di (digest di* msg) sig1 #:pad pad) "pvd pubkey sig1")
    (check-true (pk-verify-digest pubkey di (digest di* msg) sig2 #:pad pad) "pvd pubkey sig2")
    (check-true (digest/verify key di msg sig1 #:pad pad) "d/v key sig1")
    (check-true (digest/verify key di msg sig2 #:pad pad) "d/v key sig2")
    (check-true (digest/verify pubkey di msg sig1 #:pad pad) "d/v pubkey sig1")
    (check-true (digest/verify pubkey di msg sig2 #:pad pad) "d/v pubkey sig2")

    (check-false (digest/verify key di badmsg sig1 #:pad pad) "bad d/v")))

(define (test-pk-encrypt key pubkey)
  (define rsa? (eq? (send (send key get-impl) get-spec) 'rsa))
  (for ([pad (if rsa? '(pkcs1-v1.5 oaep) '(#f))])
    (define skey (semirandom-bytes 16))
    (define wkey (pk-encrypt pubkey skey #:pad pad))
    (check-equal? (pk-decrypt key wkey #:pad pad) skey "pk-decrypt")))

(define (test-pk-key-agree key1 pubkey1)
  (define params (pk-key->parameters key1))
  (define key2 (generate-private-key params))
  (define pubkey2 (pk-key->public-only-key key2))
  (check-equal? (pk-derive-secret key1 pubkey2)
                (pk-derive-secret key2 pubkey1)
                "pk-derive-secret"))


;; ----------------------------------------

(define parameters
  (list

'(dsa
  parameters
  libcrypto
  #"0\201\235\2A\0\327\21\b\264E\302\333^9\317\222\330\315\236W\265j\251\
\335\277jI\276H\1\303\353\220\327\261\373\322\244-\211\326XU$\357\262\375\
U\tn[\213\322\234'gL\304\221\202\367672\205\0o\377k\2\25\0\364\221\34_\
\215\e\366)\0\256q\323^B\aZ\277C\265\363\2A\0\314\322\232\4\6=\177\220\
\206\355\326\260\232\232\340\37\275\356L\371=f\30\345\230k\253>\311/\231\
\341\4\240j\327\341\351(\3134D%\227\2420\366\372\344\t\324\177\227}\224?\
\35g\214\201\212\27\6e")

'(dh
  parameters
  pkcs3
  #"0F\2A\0\216\243\235\221\347\267\264\251\234\321R)\36\266\34}\317\266\
\332\2001\366b\263n\231\4\36l\375\360\307\222\257=O\3\305\nI\230\276\352\
~\336\b\4\263\305\333\245\256A\274\21\306\233\2047\361\252F/\3\2\1\2")

'(ec
  parameters
  sec1
  #"0\201\307\2\1\0010$\6\a*\206H\316=\1\1\2\31\0\377\377\377\377\377\377\
\377\377\377\377\377\377\377\377\377\376\377\377\377\377\377\377\377\3770\
K\4\30\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\376\377\
\377\377\377\377\377\377\374\4\30d!\5\31\345\234\200\347\17\247\351\253r$\
0I\376\270\336\354\301F\271\261\3\25\0000E\256o\310B/d\355W\225(\323\201 \
\352\341!\226\325\0041\4\30\215\250\16\2600\220\366|\277 \353C\241\210\0\
\364\377\n\375\202\377\20\22\a\31+\225\377\310\332xc\20\21\355k$\315\325s\
\371w\241\36yH\21\2\31\0\377\377\377\377\377\377\377\377\377\377\377\377\
\231\336\3706\24k\311\261\264\322(1\2\1\1")


))


(define private-keys
  (list

'(RSAPrivateKey
  "RSA"
  #"0\202\1;\2\1\0\2A\0\275w\365\342{\273\n\n\337\340,\230\260\243\371p\0\316\206j\310\257\
\356\214F\371.\244eHV\210\307L\2\342'\357l\327Y\312k\235\306\334\24\315\322D3\273DQ\242\225\
K?tw\24\22Q\277\2\3\1\0\1\2@0q\334\320\5\35\4\353T\344\347\342>\300\36\206Q\336|\246\17\34T\
\335ODeu\251c\376\243\327&\235w\25\214\235\267;{w\36\230\221\365\324\337\315\206d\30\307\255\
s\331\206\255m-)\227\331\2!\0\366-+\303\322;\370\345]\21\256\271\255W\345k\211\262\363-\351\
\34&\330\34\244?\237Qfp\233\2!\0\305\a|\302*\316\244l\20r\371\25\rtB\227\2\272\256S\32\n3\22\
\224\370\201F\340\265\273\255\2!\0\334\f2\203\236\247\266\352\246\317\210\2046[L\32]\2\225v\
\243Yc\253g\246\265\254\36a\330#\2!\0\214>\245\36,\214D[+f;H1\370tA\273N\2301L\322\277\301\
\325J\1\363*\226\21M\2 H\300\261*\360m\267\354\231[\374\1\204\25\311\3\220|~2\307h\337\336\
\330\273\323\370\255~g\332")

;; FIXME: (generate-private-key dsaparams) causes segfault

'(PrivateKeyInfo
  "DH nbits=512, generator=2, generated by libcrypto"
  #"0\201\234\2\1\0000S\6\t*\206H\206\367\r\1\3\0010F\2A\0\265\267\350{\303\342\200\366\200\235\263\302\305\304\245\233i\205`,\204\bN\5\22rq\265\360>\246l\254\37[\201\244\222\363|\361\206\265\32\2247\306\320\337\31u\2\357\360e\343\220f\222~\270\375b\203\2\1\2\4B\2@@\e5k\317\256M\222\30\306\314jNg\0N\346[l~o/\f\311e\374\261s\240\273\240^r.\271\204\321\340.M\2664}\337A0\376\303\214*\b\nr\341\257\342\365\327\274\233\0027-U")

'(PrivateKeyInfo
  "EC secp192r1, generated by libcrypto"
  #"0o\2\1\0000\23\6\a*\206H\316=\2\1\6\b*\206H\316=\3\1\1\4U0S\2\1\1\4\30\274\242\276U\341\256d\355\304'\222\276\277\327\244\216\250\0\221w\3jr\254\2414\0032\0\4^\6\300\342\f\266\34\336<\324\245LX-\323\244\344\257\217\31\204\234\353\2769A\301oS\24\6]\320\213:\205\334\207j[\333\366kHSgK\371")
))
