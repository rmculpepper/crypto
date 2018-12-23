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
    #"M\275\226\361\355\272@\231\37\365}9\354<81$3O\256\270\331\346QFZ_5?9\312\5")))
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
    (u . #"\265\361c&2\361\301\26\273\271\264\255\334\365\313\212")
    c
    (u . #"\235\t\220s\246C\f\230if'\303M\210\314\236"))))
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
    "$argon2id$v=19$m=4096,t=1000,p=1$m+clolnAitzUfS2LdXAecw$tk4bWb9R4qjzOexnJVVkdCdKjSaZIVzjD7x7QBKZGeE")))
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
