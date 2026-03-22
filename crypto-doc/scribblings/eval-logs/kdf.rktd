;; This file was created by make-log-based-eval
((require crypto crypto/all racket/random)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((crypto-factories (list argon2-factory libcrypto-factory sodium-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((kdf
  '(pbkdf2 hmac sha256)
  #"I am the eggman"
  (crypto-random-bytes 16)
  '((iterations 100000))
  #:key-size
  32)
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (u
    .
    #"J\373h\310mfmh\266\345JWde\227\225\313Ub\201\332\1O\367f\201{\232\256\363z\330")))
 #""
 #"")
((kdf
  'argon2id
  #"I am the walrus"
  #"googoogjoob"
  '((t 100) (m 2048) (p 1))
  #:key-size
  32)
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (u
    .
    #"\30V\214|i\2072VE\242\345`+A\262\352Ni\230|6\365\227M\364\2\326y{\256\271\21")))
 #""
 #"")
((define pre-key (crypto-random-bytes 16))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((list
  (kdf '(hkdf sha256) pre-key #f '((info #"enc") (key-size 16)))
  (kdf '(hkdf sha256) pre-key #f '((info #"mac") (key-size 16))))
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (c
    (u . #"\36>\376\334H\331^\6\370\25\302gC2\362\26")
    c
    (u . #"t\4\236=\200\225\334\344\375\262&\374\267\225?b"))))
 #""
 #"")
((define pwcred (pwhash 'argon2id #"mypassword" '((m 4096) (t 10) (p 1))))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
(pwcred
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (u
    .
    "$argon2id$v=19$m=4096,t=10,p=1$dJPZCOuOJa3Foy6xCdYVLQ$1B/cNol5YfOkUKg3txiDzxR8gyyq9pyV4g6NP1x0krA")))
 #""
 #"")
((pwhash-verify #f #"mypassword" pwcred)
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
((pwhash-verify #f #"wildguess" pwcred)
 ((3) 0 () 0 () () (q values #f))
 #""
 #"")
((pbkdf2-hmac 'sha256 #"I am the walrus" #"abcd" #:iterations 100000)
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (u
    .
    #"\aR>\"^\241\301\253f\v\237\310\263\330T\321\301\307|\212`\370\rD\347\f`{>\226c\371")))
 #""
 #"")
