;; This file was created by make-log-based-eval
((require crypto crypto/libcrypto)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((crypto-factories (list libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((kdf
  '(pbkdf2 hmac sha256)
  #"I am the walrus"
  #"abcd"
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
    #"\aR>\"^\241\301\253f\v\237\310\263\330T\321\301\307|\212`\370\rD\347\f`{>\226c\371")))
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
