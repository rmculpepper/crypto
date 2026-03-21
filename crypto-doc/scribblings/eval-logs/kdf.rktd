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
  '((iterations 100000) (key-size 32)))
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
    #"\232v\203P':(h\373\222\265\16#\374\373\20\317Rz\26vS\360\200\6\355UPm\17\352\6")))
 #""
 #"")
((kdf
  'argon2id
  #"I am the walrus"
  #"googoogjoob"
  '((t 100) (m 2048) (p 1) (key-size 32)))
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
    (u . #" Fq\223L\36\16T\331\214\4\253\272\202\356\r")
    c
    (u . #"\376_\21\202\320i\203\20\251\363\373\222'#\371\310"))))
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
    "$argon2id$v=19$m=4096,t=10,p=1$+IVbyVp7GvrbCxetj1N0Hg$2ySdH3AeiBWVr8pcmWA9WVUW+QLn3ejZrPPq+zFxR7I")))
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
