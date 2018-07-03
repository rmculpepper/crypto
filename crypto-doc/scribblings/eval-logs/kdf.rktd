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
    #"^\225?\a\315A\366\245\205\3A\207?\233_\235E\316\304\275\373\252\207\362\260\3518\v\240\a\243m")))
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
((define pwcred (pwhash 'argon2id #"mypassword" '((t 1000) (m 4096) (p 1))))
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
    "$argon2id$v=19$m=4096,t=1000,p=1$ZDVdF0LT1XFZ+5vcNtNBxA$S+5b8J57xaqdtK37F4E4Bgmgd/4STtd6JeuFjSI7n9k")))
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
