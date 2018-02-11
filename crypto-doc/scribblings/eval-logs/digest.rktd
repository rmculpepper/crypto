;; This file was created by make-log-based-eval
((require crypto crypto/libcrypto)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((crypto-factories (list libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest-size 'sha1) ((3) 0 () 0 () () (q values 20)) #"" #"")
((digest-size 'sha256) ((3) 0 () 0 () () (q values 32)) #"" #"")
((digest-block-size 'sha1) ((3) 0 () 0 () () (q values 64)) #"" #"")
((digest 'sha1 "Hello world!")
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (u . #"\323Hj\351\23nxV\274B!#\205\352yp\224GX\2")))
 #""
 #"")
((digest 'sha256 "Hello world!")
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
    #"\300S^K\342\267\237\375\223)\23\5Ck\370\2111NJ?\256\300^\317\374\273}\363\32\331\345\32")))
 #""
 #"")
((define dctx (make-digest-ctx 'sha1))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest-update dctx "Hello ") ((3) 0 () 0 () () (c values c (void))) #"" #"")
((digest-update dctx "world!") ((3) 0 () 0 () () (c values c (void))) #"" #"")
((digest-final dctx)
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (u . #"\323Hj\351\23nxV\274B!#\205\352yp\224GX\2")))
 #""
 #"")
