;; This file was created by make-log-based-eval
((require crypto crypto/util/bech32)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((bech32-encode "age" #"1234567890abcdef1234567890UVWXYZ")
 ((3)
  0
  ()
  0
  ()
  ()
  (c
   values
   c
   (u . "age1xyerxdp4xcmnswfsv93xxer9vccnyve5x5mrwwpexp24v46ct9dq3wvnf4")))
 #""
 #"")
((bech32-decode
  "age1xyerxdp4xcmnswfsv93xxer9vccnyve5x5mrwwpexp24v46ct9dq3wvnf4")
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (c (u . "age") c (u . #"1234567890abcdef1234567890UVWXYZ"))))
 #""
 #"")
((bech32-decode
  "age1xyerxdp4xcmnswfsv93xxer9vccnyve5x5mrwwpexp24v46ct9dq3wvnf")
 ((3) 0 () 0 () () (q exn "bech32-decode: invalid checksum"))
 #""
 #"")
