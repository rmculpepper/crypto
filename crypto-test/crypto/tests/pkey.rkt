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
        (eprintf "-  cannot read ~s (~a)\n" (cadr key-sexpr) factory-name)))
    (when key
      (when #t
        (eprintf "+  testing ~s (~a)\n" (cadr key-sexpr) factory-name))
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
            (eprintf " - cannot read public key for ~s (~s)\n"
                     (cadr key-sexpr) (send pub-factory get-name))))
        (when pubkey*
          (when #t
            (eprintf " + cross-testing with ~s\n" (send pub-factory get-name)))
          ;; (check public-key=? pubkey pubkey*) ;; FIXME?
          (test-case (format "~a => ~a, ~a ~a" factory-name (send pub-factory get-name)
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

(define (sign-pad-ok? key pad)
  (case pad
    [(pkcs1-v1.5) #t]
    [(pss) (memq (send (get-factory key) get-name) '(libcrypto #;gcrypt nettle))]
    [(pss*) (memq (send (get-factory key) get-name) '(libcrypto))]))

(define (test-pk-sign key pubkey)
  (define rsa? (eq? (send (send key get-impl) get-spec) 'rsa))
  (for* ([pad (if rsa? '(pkcs1-v1.5 pss pss*) '(#f))])
    (define pad-ok? (and (sign-pad-ok? key pad) (sign-pad-ok? pubkey pad)))
    (unless pad-ok?
      (eprintf "  -skipping pad = ~v\n" pad))
    (when pad-ok?
      (eprintf "  +testing pad = ~v\n" pad)
      (for ([di '(sha1 sha256)])
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
        (check-false (digest/verify key di badmsg sig1 #:pad pad) "bad d/v")))))

(define (encrypt-pad-ok? key pad)
  (case pad
    [(pkcs1-v1.5) #t]
    [(oaep) (memq (send (get-factory key) get-name) '(libcrypto gcrypt))]))

(define (test-pk-encrypt key pubkey)
  (define rsa? (eq? (send (send key get-impl) get-spec) 'rsa))
  (for ([pad (if rsa? '(pkcs1-v1.5 oaep) '(#f))]
        #:when (and (encrypt-pad-ok? key pad) (encrypt-pad-ok? pubkey pad)))
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
  "RSA nbits=1024"
  #"0\202\2^\2\1\0\2\201\201\0\301\32Y\264uX\352\6\21=\325\206r\311\207\21-\247\357\242\324a\2416y)\225\4\365=X\361f\277\326\351z\346p\337\336\24\314\274\247llHU>k\35zc\205sj(\352\22}\216\375\366p\311&\1\37z5\234tB\243\300h\377%\266c\262\e{\325\363\345\300\357\260\334\22a\367\371\n\252\37\346IC\303&\215\2\242\34%\367\376\252\253C\356V\235\20\320\264\323m{\251N\353F\34\343\2\3\1\0\1\2\201\201\0\237\220\361\255\200\6\200#\221]\3022\376ioV\17\237%\23-b\233\177\322\361<u\303\\\365AM\201\232\312\206G#\340\251\270\20R\230\32\255\3\274\204\376\250v9\4\316\221[\313\310\211\276~6\23\2066\235\4@\376}\332\234\240\235\345\322\342\4\331\v\244a\360\332wH\vm\241\355{\4M\367\223\321b \23waT\356\376\301.\343+\1e\333\366\261)\337t\16\305\220\366\225\"\200B\334y\2A\0\372K(!&\271|sY\351\vy\307PU\221b\375qI\344\5M\334\346\35q_v'~\201\235\241\232\326\vb\31 \300\237\21 \"\30\235\263\337\20l\r\213\211}b])\375\221o=\363\255\2A\0\305\201f;\31\27cBT\323\332C\3067*\23VFQ\19\307C:\2740W\321k\316\354i\331\271D7 (\336\366v\362\277f1KVK\177\206\207vV\a\312\201y\27c\233\234\310\344\317\2A\0\275\3305\306\367eg\204\342\344\205\304\307\256\"I\25Ia\35\207\253\222D\203\362?%\6,\254\242\311\232c$\t\34N,\356\215xb\344\31\301\274E\354a\330\340F\327\350\274\373u\216SO-=\2A\0\247\b\rnS\205\r\3\356\373\217\356\233v\321\325\262\264\e\23\277J~\327\360\211\255\353E\222\245+\313\337<\n\246\337\t\331D\265}\e.\3738\312\366\331\316<L\373\237\316\251\233\279fz\e\317\2@E\266`\312&'B~-\253]\225\307\256;\2671\345\2777\215\21\223\2263Y\247\310\232\16\242\e\377\351\347\0\270\4\231\234\320\221#;\r$%\254\177V\250\274Z\233\22\242*\254\nZ\30\374]\300")

;; FIXME: (generate-private-key dsaparams) causes segfault

'(PrivateKeyInfo
  "DH nbits=512, generator=2, generated by libcrypto"
  #"0\201\234\2\1\0000S\6\t*\206H\206\367\r\1\3\0010F\2A\0\265\267\350{\303\342\200\366\200\235\263\302\305\304\245\233i\205`,\204\bN\5\22rq\265\360>\246l\254\37[\201\244\222\363|\361\206\265\32\2247\306\320\337\31u\2\357\360e\343\220f\222~\270\375b\203\2\1\2\4B\2@@\e5k\317\256M\222\30\306\314jNg\0N\346[l~o/\f\311e\374\261s\240\273\240^r.\271\204\321\340.M\2664}\337A0\376\303\214*\b\nr\341\257\342\365\327\274\233\0027-U")

'(PrivateKeyInfo
  "EC secp192r1, generated by libcrypto"
  #"0o\2\1\0000\23\6\a*\206H\316=\2\1\6\b*\206H\316=\3\1\1\4U0S\2\1\1\4\30\274\242\276U\341\256d\355\304'\222\276\277\327\244\216\250\0\221w\3jr\254\2414\0032\0\4^\6\300\342\f\266\34\336<\324\245LX-\323\244\344\257\217\31\204\234\353\2769A\301oS\24\6]\320\213:\205\334\207j[\333\366kHSgK\371")
))
