;; Copyright 2012-2018 Ryan Culpepper
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
         racket/match
         rackunit
         crypto
         "util.rkt")
(provide (all-defined-out))

;; Sign/verify
;;  - privkey signs, privkey verifies, pubkey verifies, privkey2 doesn't verify

;; Encrypt/decrypt
;;  - privkey encrypts, privkey decrypts
;;  - pubkey encrypts, privkey decrypts
;;  - privkey encrypts, privkey2 doesn't decrypt

;; Key agreement
;;  - privkey1+pubkey2 derives same key as privkey2+pubkey11

(define (readkey sexpr factory)
  (match-define (list* fmt pkspec desc keydata more) sexpr)
  (define privkey
    (with-handlers ([exn:fail? (lambda (e) #f)])
      (datum->pk-key keydata fmt factory)))
  (define pubkey0
    (match more
      ['() #f]
      [(list pub-fmt pub-keydata)
       (with-handlers ([exn:fail? (lambda (e) 'fail)])
         (datum->pk-key pub-keydata pub-fmt factory))]))
  (values privkey pubkey0))

(define (test-pk factory [pub-factories null] #:keygen? [keygen? #f])
  (define factory-name (send factory get-name))
  (when keygen?
    (for ([pk '(rsa dsa dh ec eddsa ecx)] #:when (get-pk pk factory))
      (test-keygen factory pk (get-pk pk factory))))
  (test-pk-pubkeys factory)
  (for ([key-sexpr private-keys]
        #:when (let ([fmt (car key-sexpr)] [pkspec (cadr key-sexpr)])
                 (and (send factory get-pk pkspec) (pk-format-ok? factory pkspec fmt))))
    (match-define (list* fmt pkspec desc keydata _) key-sexpr)
    (define-values (key pubkey0) (readkey key-sexpr factory))
    (define pubkey (and key (pk-key->public-only-key key)))
    (unless key
      (when #t
        (hprintf -1 "ERROR: ~a cannot read ~s\n" (send factory get-name) desc)))
    (when key
      (when #t
        (hprintf 1 "testing ~s (~a)\n" desc factory-name)
        (hprintf 2 "self-test (~a => ~a)\n" factory-name factory-name))
      (test-case (format "~a ~a ~a" factory-name desc fmt)
        (check-pred private-key? key)
        (check-pred public-only-key? pubkey)
        (when pubkey0
          (check-pred public-only-key? pubkey0)
          (check public-key=? key pubkey0)
          (check public-key=? pubkey0 pubkey))
        (check public-key=? key pubkey)
        (test-pk-serialize key pubkey factory)
        (test-pk-key key pubkey))
      (define pubkey-der (pk-key->datum pubkey 'SubjectPublicKeyInfo))
      (for ([pub-factory (remove factory pub-factories)]
            #:when (memq (send key get-spec) (send pub-factory info 'all-pks)))
        (define pubkey*
          (with-handlers ([exn:fail? (lambda (e) #f)])
            (datum->pk-key pubkey-der 'SubjectPublicKeyInfo pub-factory)))
        (unless pubkey*
          (when #t
            (hprintf -2 "ERROR: ~a cannot read public key for ~s\n"
                     (send pub-factory get-name) desc)))
        (when pubkey*
          (when #t
            (hprintf 2 "cross-testing (~a => ~a)\n"
                     factory-name (send pub-factory get-name)))
          (test-case (format "~a => ~a, ~a ~a" factory-name (send pub-factory get-name) fmt desc)
            (test-pk-key key pubkey*)))))))

(define (test-keygen factory spec impl)
  (define (test-rt-equal privkey)
    (when (pk-format-ok? factory (send privkey get-spec) 'rkt-private)
      (define privkey2
        (datum->pk-key (pk-key->datum privkey 'rkt-private) 'rkt-private factory))
      (check public-key=? privkey privkey2))
    (when (pk-format-ok? factory (send privkey get-spec) 'rkt-public)
      (define pubkey2
        (datum->pk-key (pk-key->datum privkey 'rkt-public) 'rkt-public factory))
      (check public-key=? privkey pubkey2)))
  (test-case (format "~a ~a keygen" (send factory get-name) spec)
    (define factory-name (send factory get-name))
    (hprintf 1 "testing keygen for ~s (~a)\n" spec factory-name)
    (case spec
      [(rsa)
       (check-false (pk-has-parameters? impl))
       (test-rt-equal (generate-private-key impl '((nbits 512))))]
      [(dsa)
       (case factory-name
         [(gcrypt)  ;; params not implemented
          (void)]
         [else
          (check-true (pk-has-parameters? impl))
          (define p (generate-pk-parameters impl '((nbits 1024))))
          (test-rt-equal (generate-private-key p))])
       (test-rt-equal (generate-private-key impl '((nbits 1024))))]
      [(dh)
       (check-true (pk-has-parameters? impl))
       (define p (generate-pk-parameters impl '((nbits 512))))
       (test-rt-equal (generate-private-key p))
       (test-rt-equal (generate-private-key impl '((nbits 512))))]
      [(ec)
       (check-true (pk-has-parameters? impl))
       (define p1 (generate-pk-parameters impl '((curve "secp192r1"))))
       (define p2 (generate-pk-parameters impl '((curve secp256r1))))
       (test-rt-equal (generate-private-key p1))
       (test-rt-equal (generate-private-key p2))
       (test-rt-equal (generate-private-key impl '((curve secp192r1))))]
      [(eddsa)
       (define k (generate-private-key impl '((curve ed25519))))
       (check-pred private-key? k)
       (test-rt-equal k)
       (define p (generate-pk-parameters impl '((curve ed25519))))
       (check-pred pk-parameters? p)
       (define k2 (generate-private-key p '()))
       (check-pred private-key? k2)
       (test-rt-equal k)
       (check-equal? (pk-parameters->datum p 'rkt-params)
                     (pk-parameters->datum (pk-key->parameters k) 'rkt-params))]
      [(ecx)
       (define k (generate-private-key impl '((curve x25519))))
       (check-pred private-key? k)
       (test-rt-equal k)
       (define p (generate-pk-parameters impl '((curve x25519))))
       (check-pred pk-parameters? p)
       (define k2 (generate-private-key p '()))
       (check-pred private-key? k2)
       (test-rt-equal k2)
       (check-equal? (pk-parameters->datum p 'rkt-params)
                     (pk-parameters->datum (pk-key->parameters k) 'rkt-params))]
      [else (void)])))

(define (test-pk-pubkeys factory)
  (define factory-name (send factory get-name))
  (for ([key-sexpr (in-list public-keys)])
    (match-define (list fmt pkspec desc keydata) key-sexpr)
    (define pubkey (with-handlers ([exn:fail? (lambda (e) #f)])
                     (datum->pk-key keydata fmt factory)))
    (unless pubkey
      (when #t
        (hprintf -1 "ERROR: ~a cannot read public ~s\n" factory-name desc)))
    (when pubkey
      (when #t
        (hprintf 1 "testing public ~s (~a)\n" desc factory-name))
      (test-case (format "~a ~a ~a" factory-name desc fmt)
        (check-pred pk-key? pubkey)
        (check-pred public-only-key? pubkey)))))

(define (test-pk-serialize key pubkey factory)
  ;; can serialize and deserialize private keys, and serialized format is canonical
  (for ([fmt '(PrivateKeyInfo OneAsymmetricKey rkt-private)]
        #:when (pk-format-ok? factory (send key get-spec) fmt))
    (define keydata (pk-key->datum key fmt))
    (define key2 (datum->pk-key keydata fmt factory))
    (check-pred private-key? key2)
    (check public-key=? key2 key)
    (check-equal? (pk-key->datum key2 fmt) keydata))
  ;; likewise for public keys
  (for ([fmt '(SubjectPublicKeyInfo rkt-public)])
    (define pubdata (pk-key->datum key fmt))
    (define pubkey2 (datum->pk-key pubdata fmt factory))
    (check-pred public-only-key? pubkey2)
    (check public-key=? pubkey2 key)
    (check public-key=? pubkey2 pubkey)
    (check-equal? (pk-key->datum pubkey2 fmt) pubdata))
  ;; likewise for params, if available
  (when (pk-has-parameters? key)
    (define params (pk-key->parameters key))
    (for ([fmt '(AlgorithmIdentifier rkt-params)])
      (define pdata (pk-parameters->datum params fmt))
      (define params2 (datum->pk-parameters pdata fmt factory))
      (check-equal? (pk-parameters->datum params fmt) pdata))))

(define (pk-format-ok? factory kspec fmt)
  (define fname (send factory get-name))
  (not (or
        ;; gcrypto cannot roundtrip EdDSA key via PrivateKeyInfo (missing public key part)
        (and (memq fname '(gcrypt)) (memq kspec '(eddsa ecx))
             (memq fmt '(PrivateKeyInfo age/v1-private))))))

(define (test-pk-key key pubkey)
  (when (and (pk-can-sign? key) (pk-can-sign? pubkey))
    (test-pk-sign key pubkey))
  (when (and (pk-can-encrypt? key) (pk-can-encrypt? pubkey))
    (test-pk-encrypt key pubkey))
  (when (and (pk-can-key-agree? key) (pk-can-key-agree? pubkey))
    (test-pk-key-agree key pubkey)))

(define msg #"I am the walrus.")
(define badmsg #"I am the egg nog.")

(define (test-pk-sign key pubkey)
  (define spec (send (send key get-impl) get-spec))
  (case spec
    [(eddsa) (test-eddsa-sign key pubkey)]
    [(rsa) (test-pk-sign* key pubkey '(pkcs1-v1.5 pss pss*))]
    [else  (test-pk-sign* key pubkey '(#f))]))

(define (test-eddsa-sign key pubkey)
  (hprintf 3 "testing sign direct\n")
  (define sig (pk-sign key msg))
  (check-true (pk-verify key msg sig))
  (check-true (pk-verify pubkey msg sig))
  (check-false (pk-verify key badmsg sig))
  (check-false (pk-verify pubkey badmsg sig)))

(define (test-pk-sign* key pubkey pads)
  (for* ([pad pads])
    (define pad-ok? (and (pk-can-sign? key pad) (pk-can-sign? pubkey pad)))
    (unless pad-ok?
      (hprintf -3 "skipping sign w/ pad = ~v\n" pad))
    (when pad-ok?
      (for ([di '(sha1 sha256)])
        (cond [(and (pk-can-sign? key pad di) (pk-can-sign? pubkey pad di))
               (hprintf 3 "testing sign w/ pad = ~v, digest = ~v\n" pad di)
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
               (check-false (digest/verify key di badmsg sig1 #:pad pad) "bad d/v")]
              [else (hprintf -3 "skipping sign w/ pad = ~v, digest = ~v\n" pad di)])))))

(define (encrypt-pad-ok? key pad)
  (case pad
    [(pkcs1-v1.5) #t]
    [(oaep) (memq (send (get-factory key) get-name) '(libcrypto gcrypt))]))

(define (test-pk-encrypt key pubkey)
  (define rsa? (eq? (send (send key get-impl) get-spec) 'rsa))
  (for ([pad (if rsa? '(pkcs1-v1.5 oaep) '(#f))])
    (cond [(and (pk-can-encrypt? key pad) (pk-can-encrypt? pubkey pad))
           (hprintf 3 "testing encrypt w/ pad = ~v\n" pad)
           (define skey (semirandom-bytes 16))
           (define wkey (pk-encrypt pubkey skey #:pad pad))
           (check-equal? (pk-decrypt key wkey #:pad pad) skey "pk-decrypt")]
          [else (hprintf -3 "skipping encrypt w/ pad = ~v\n" pad)])))

(define (test-pk-key-agree keyA1 pubkeyB1)
  ;; A,B are factories; 1,2 are parties
  (hprintf 3 "testing key agreement\n")
  (define keyB2 (generate-private-key (pk-key->parameters pubkeyB1)))
  (define pubkeyA2 (datum->pk-key (pk-key->datum keyB2 'SubjectPublicKeyInfo)
                                 'SubjectPublicKeyInfo (get-factory keyA1)))
  (check-equal? (pk-derive-secret keyA1 pubkeyA2)
                (pk-derive-secret keyB2 pubkeyB1)
                "pk-derive-secret")
  ;; test that keys of different impls work (auto-convert)
  (check-equal? (pk-derive-secret keyA1 (pk-key->public-only-key keyB2))
                (pk-derive-secret keyB2 (pk-key->public-only-key keyA1))))

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


(define public-keys
  (list

'(openssh-public
  eddsa "openssh Ed25519, no comment"
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAUYR9NImwLChDL638Iy3VcHTBeRiW4N+PyOA77BC71F")

))

(define private-keys
  (list

'(RSAPrivateKey
  rsa "RSA nbits=1024"
  #"0\202\2^\2\1\0\2\201\201\0\301\32Y\264uX\352\6\21=\325\206r\311\207\21-\247\357\242\324a\2416y)\225\4\365=X\361f\277\326\351z\346p\337\336\24\314\274\247llHU>k\35zc\205sj(\352\22}\216\375\366p\311&\1\37z5\234tB\243\300h\377%\266c\262\e{\325\363\345\300\357\260\334\22a\367\371\n\252\37\346IC\303&\215\2\242\34%\367\376\252\253C\356V\235\20\320\264\323m{\251N\353F\34\343\2\3\1\0\1\2\201\201\0\237\220\361\255\200\6\200#\221]\3022\376ioV\17\237%\23-b\233\177\322\361<u\303\\\365AM\201\232\312\206G#\340\251\270\20R\230\32\255\3\274\204\376\250v9\4\316\221[\313\310\211\276~6\23\2066\235\4@\376}\332\234\240\235\345\322\342\4\331\v\244a\360\332wH\vm\241\355{\4M\367\223\321b \23waT\356\376\301.\343+\1e\333\366\261)\337t\16\305\220\366\225\"\200B\334y\2A\0\372K(!&\271|sY\351\vy\307PU\221b\375qI\344\5M\334\346\35q_v'~\201\235\241\232\326\vb\31 \300\237\21 \"\30\235\263\337\20l\r\213\211}b])\375\221o=\363\255\2A\0\305\201f;\31\27cBT\323\332C\3067*\23VFQ\19\307C:\2740W\321k\316\354i\331\271D7 (\336\366v\362\277f1KVK\177\206\207vV\a\312\201y\27c\233\234\310\344\317\2A\0\275\3305\306\367eg\204\342\344\205\304\307\256\"I\25Ia\35\207\253\222D\203\362?%\6,\254\242\311\232c$\t\34N,\356\215xb\344\31\301\274E\354a\330\340F\327\350\274\373u\216SO-=\2A\0\247\b\rnS\205\r\3\356\373\217\356\233v\321\325\262\264\e\23\277J~\327\360\211\255\353E\222\245+\313\337<\n\246\337\t\331D\265}\e.\3738\312\366\331\316<L\373\237\316\251\233\279fz\e\317\2@E\266`\312&'B~-\253]\225\307\256;\2671\345\2777\215\21\223\2263Y\247\310\232\16\242\e\377\351\347\0\270\4\231\234\320\221#;\r$%\254\177V\250\274Z\233\22\242*\254\nZ\30\374]\300")

'(PrivateKeyInfo
  dsa "DSA nbits=1024" ;; generated by gcrypt
  #"0\202\1c\2\1\0000\202\0017\6\a*\206H\3168\4\0010\202\1*\2\201\201\0\271\372\305\6\212\31\233\337\260K\264\206\217d\334f\362P\"[B\200W'PxD[w\312\351,\350Ld'Y\314\1\207m\314\307\17\357+\202o'm\3435\5\e\277\225\322\256\300\0\2537 \217\343~P4\302\265\333]wh\257\b\351\205\317\f[\2F\302jW\234\247\351\203\36759V\243\220\35?Q\37\264\236\306jkv\207\261\225\310\236\377\0011\217\17\34\2440_\vE\311\3\276\273\363\257\2!\0\376\212\222\240\275F\376P\275\201=\177\253\265*t\3p\211\313!\225\303\325\366\243\341\217\200\34wm\2\201\200D^\263R\230[\3\215\312\261\302\260\232\37\313X\257\315|\211^\250\22\256\360.0\34\330\22\303k\270\240DK\321\356\17\335\317hX=\351\221*\372\257p\367A\252\216\234\243\37w\356W\202\232\266\322_-\310\347\1\0256\252S$\231%,M>\250\247\243\260\36U\351\201\203\376;0\201\26\251\n\30`cz\303Y\302\322G#^\271$2\370\312\227\v\0341\25\251\341d\311t\"{b\226\322\357\221\4#\2!\0\2541f\357\334N\220\e-L\304\246\314\207&\231HA\1\276\320O\26\25\237\234\307:c\364\214\226")

'(PrivateKeyInfo
  dh "DH nbits=512, generator=2" ;; generated by libcrypto
  #"0\201\234\2\1\0000S\6\t*\206H\206\367\r\1\3\0010F\2A\0\265\267\350{\303\342\200\366\200\235\263\302\305\304\245\233i\205`,\204\bN\5\22rq\265\360>\246l\254\37[\201\244\222\363|\361\206\265\32\2247\306\320\337\31u\2\357\360e\343\220f\222~\270\375b\203\2\1\2\4B\2@@\e5k\317\256M\222\30\306\314jNg\0N\346[l~o/\f\311e\374\261s\240\273\240^r.\271\204\321\340.M\2664}\337A0\376\303\214*\b\nr\341\257\342\365\327\274\233\0027-U")

'(PrivateKeyInfo
  ec "EC secp192r1" ;; generated by libcrypto
  #"0o\2\1\0000\23\6\a*\206H\316=\2\1\6\b*\206H\316=\3\1\1\4U0S\2\1\1\4\30\274\242\276U\341\256d\355\304'\222\276\277\327\244\216\250\0\221w\3jr\254\2414\0032\0\4^\6\300\342\f\266\34\336<\324\245LX-\323\244\344\257\217\31\204\234\353\2769A\301oS\24\6]\320\213:\205\334\207j[\333\366kHSgK\371")

'(PrivateKeyInfo
  ec "EC secp256r1" ;; generated by libcrypto
  #"0\201\207\2\1\0000\23\6\a*\206H\316=\2\1\6\b*\206H\316=\3\1\a\4m0k\2\1\1\4 z\354\307\203k\264y\23i\364\f\354\232^\343\314i\350\371l\277~\210<,\260hDA\363\315h\241D\3B\0\4\300NyL$\22\27\342\276\363Vj:\251\352\324Aog\263\233\224d\267Wj\31\271\303\274\360\3179\232\275\303\243;\230\311\251\236\316\364}\305\217\320\313\336@\263\326a\t;e\23\211\0\21\271$\324")

'(PrivateKeyInfo
  eddsa "Ed25519, PKI" ;; generated by libsodium
  #"0.\2\1\0000\5\6\3+ep\4\"\4 \311\320\325\354\357\e\f\354[\350\310\251'v\223J\344\336\203J=!\375\302\227H\272\35>\251\214\r")

'(OneAsymmetricKey
  eddsa "Ed25519, OAK" ;; generated by libsodium
  #"0Q\2\1\0010\5\6\3+ep\4\"\4 \311\320\325\354\357\e\f\354[\350\310\251'v\223J\344\336\203J=!\375\302\227H\272\35>\251\214\r\201!\0\37\363\361\366\2\245\271\36\346\3267\1\\hd\365]\3C\312O6|\v:\212\200\277H^\17\221")

'(PrivateKeyInfo
  ecx "X25519"
  #"0.\2\1\0000\5\6\3+en\4\"\4 9u\231\360\3\\<^c\222zL\347V\241w\344\336\360\t\322\241\336^\236\264\266{`\252I\346")

'(PrivateKeyInfo
  eddsa "Ed448, PKI"  ;; generated by libcrypto
  #"0G\2\1\0000\5\6\3+eq\4;\49*'\232\223g\307m\2E$>UG!O\261\307\327\272w\276\320\3\243\354u\203\364\243\307K\372\177\266\312P\3\361\f\3605\320\311\227\230\31PW\325,\263\340%#\rPW")

'(PrivateKeyInfo
  ecx "X448, PKI"  ;; generated by libcrypto
  #"0F\2\1\0000\5\6\3+eo\4:\48\225\303\342\267\366-\255KBX\312\6\257\205G\307\253\26]\22\335\341\363d\333\330>\252\373\314\24H`\256\245z\3\v\226\374\f\336F\302k-\370r\353\e\343[h\327\237\320")

'(age/v1-private
  ecx "age X25519"
  "AGE-SECRET-KEY-1HCLVK75SHR72D76JXW79WPXUYFATQ902QXZU9E2HJ3MT2A86XM2QEDAAJP"
  age/v1-public
  "age1qlaaen79yp8yg4qacrvxurqzf7csunkzpexmxmmcd9dv595wk35q3kjvzv")

'(PrivateKeyInfo
  rsa "openssh RSA nbits=2048, comment"
  #"0\202\4\275\2\1\0000\r\6\t*\206H\206\367\r\1\1\1\5\0\4\202\4\2470\202\4\243\2\1\0\2\202\1\1\0\247=\257\32\bX\365\343&\351Z\362[\237-\224U\223\271\353\267\221\372\265\337%\357\363\206L\4\"\0\356\36:\212\305\0\373\371{\220\256\332\351;r\244\377\207r\324T\320(\263\36\0QW\\\322\275\317\351\306\207\241\270\3410(\221\337Q\4\271\275\204\263\227\323 \323\331\217=\325\237,+faD\305\250\"2X\316\237H\346\337\334,\27aD\244\31\321\303\26\273\230\361\27\335^\215\317,\361[\262I7\234\240\353MEk\362\347k[\274\335:q\263N\237y\345\376;IzX\315\252$\320\1WqZ\353\247\273\325][#\261\217\316\206q\30%\27\241]\221\f8\252F\347_8\267\37\f\206\222\21F\311\207\316\322 \1.o#\313\337\235\32\304\244\277\366b\273\6\346\207\365\16\260\375V\222Ml\312\24\23L\361\372\200\277\315\303l\355Eq\2\255\317\207\231\317\306\370\ea\275\203\325\246\f(\253\257\305\2\3\1\0\1\2\202\1\0G)\341K\223\207\277A\244:\"\0\4\352\253\353u\252\301\257B\322\264;\25\264?\361\201\20\361\245B~\20\220\332\241\317\264h\311\242\2344\374\217\326M\315\211\346[\341\247\35\332r\6\262\226\31\"w\260t\n\215\206LtN\30\305Q\240Y\1lZ~M9\202\273\202\325\a\373\321\232j\361J\254\207\352\356z;\375\330\e\236Z]\206\311\200\23D<\324\\N]\17Lo\332;\264\336\26\202\261\201 $p\343-\r\310\361yol\361\244\213\243{S\201p\342W&\240\355\357\370k\262[>\261\206\354\211r\247\341.\371\266\252\0k=\31\353\177\320o\267\220\375w\30\377\361<\3646\1\376\334\351\260\372\326|_\32(p\177\320\371l\26\341\24=D\324\310\361\327\353\37l\357\211\335\315\240\25\235\344LPX\345!9g\344Wkj\204\240\302/%\241\177\202\204\306.\364\207\27\345_J\213\3651\354U\201\2\201\201\0\327\322{Y2\240f\211k\344\300\\N\212\270\312\210=\345\342\224}\345 \264\220y\363\275n_\234\345\247pWx5\275>\245\357 \323\370\323\330\230\252\352Hq_\377\323/\243*\352\217\2k\360x,\224\303T\310\335=\"\262\25\235\24h\220U\0222U\334\232kdEP\244\242\210\375\324\246\t\325W{\350rN\375\252\6\244hP\27Q\246\253\276\246\252.&H\264\233[i<\222\277:\341\a\241\2\201\201\0\306_\362\255\210\263\330$x\v\vw\357\235\345/\37g\200P\34\206\342\275q3\251[\227\352\17\264\315f\245\256O1l\231\352\223\351\345\302\367Sn[1{U\f\31\270.\261^l\235\217\363}6\226\252TA\266e\236\233\31P\27|\4\256\307F\333\230kY\223%8\351\322\6\aBv\37\364\32L\207$\236\271z\35\n\225\271\24E\325\306e\261\263\205=/\3W\221\262\nq+\6\24W\245\245\2\201\201\0\2320\30\311\247\376\252b\301?c\"OF\2220\267\327(\366\220I\3059qf\312\211\225+V\211\274\24\274\220\361#\313y\a\211h\265\247\316\211\256\300d\262\256\264\374\n\377\274\235\273\207\302\36%ee\314>$\303\2003\336&\306\204;\201\\\244:d\325\254\316q\254\350Lm\342d\346\233V\250-\317\333\211<\251,V\235z5\300\nx\336\17S\34\264\366U\211\231\346h\17.$U\24\226\222!\2\201\200\31\252J<wfE=\232\246[*~>\340j\363V1\274\253\244+\353\264\234\251y\2472\352+K3\317\225\270\273=@\300\237\270p8\204E0\16\356\\\365\210\346>\365\23\217\222\337\343\302\355\335E*\356Q\276&q\231\301q\242H2V\346\203]_\337\353\253\344\361\363\26p\37:S\f\31I\331\302\326S\16\316$\271\274\333@+4\330AI\367^\362\246\205y+\351k\376nA\220\0322\335\2\201\200*\261\237\25\342\353\261~2\23\307b\213\274\f\243\216\226\343\21K\304\340\320]Mr\277 V\352\375U\351\276\302r\272Lw49\r\224/\3D\342\361\204-u/j\326b\316%Ln\364;\30\207\17:\6\343\340\337\30Ul\357\323T\252l\261!\6!\20\215e\2639\255\2600\3f\304\276\3639E\2715\242$\361\322.w\"\345\0'\222\223K'\310\251\31\277\246M\244[|\327|]\237\317q"
  openssh-public
  "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCnPa8aCFj14ybpWvJbny2UVZO567eR+rXfJe/zhkwEIgDuHjqKxQD7+XuQrtrpO3Kk/4dy1FTQKLMeAFFXXNK9z+nGh6G44TAokd9RBLm9hLOX0yDT2Y891Z8sK2ZhRMWoIjJYzp9I5t/cLBdhRKQZ0cMWu5jxF91ejc8s8VuySTecoOtNRWvy52tbvN06cbNOn3nl/jtJeljNqiTQAVdxWuunu9VdWyOxj86GcRglF6FdkQw4qkbnXzi3HwyGkhFGyYfO0iABLm8jy9+dGsSkv/Ziuwbmh/UOsP1Wkk1syhQTTPH6gL/Nw2ztRXECrc+Hmc/G+BthvYPVpgwoq6/F test")

))
