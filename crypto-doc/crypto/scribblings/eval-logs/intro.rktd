;; This file was created by make-log-based-eval
((require crypto crypto/libcrypto racket/match)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((require crypto) ((3) 0 () 0 () () (c values c (void))) #"" #"")
((require crypto/libcrypto) ((3) 0 () 0 () () (c values c (void))) #"" #"")
((crypto-factories (list libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
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
((define sha1-impl (get-digest 'sha1 libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest sha1-impl "Hello world!")
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (u . #"\323Hj\351\23nxV\274B!#\205\352yp\224GX\2")))
 #""
 #"")
((define skey #"VeryVerySecr3t!!")
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define iv (make-bytes (cipher-iv-size '(aes ctr)) 0))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((encrypt '(aes ctr) skey iv "Hello world!")
 ((3) 0 () 0 () () (c values c (u . #"wu\345\215\e\16\256\355.\242\30x")))
 #""
 #"")
((define iv (generate-cipher-iv '(aes ctr)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
(iv
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (u . #"\351\256\17\\f\3505l\227\235\17\0007\376\vu")))
 #""
 #"")
((cipher-iv-size '(aes ctr)) ((3) 0 () 0 () () (q values 16)) #"" #"")
((define key (generate-cipher-key '(aes gcm)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define iv (generate-cipher-iv '(aes gcm)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define ct (encrypt '(aes gcm) key iv #"Nevermore!" #:aad #"quoth the raven"))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((decrypt '(aes gcm) key iv ct #:aad #"quoth the raven")
 ((3) 0 () 0 () () (c values c (u . #"Nevermore!")))
 #""
 #"")
((decrypt '(aes gcm) key iv ct #:aad #"said the bird")
 ((3) 0 () 0 () () (q exn "decrypt: authenticated decryption failed"))
 #""
 #"")
((define sha1-ctx (make-digest-ctx 'sha1))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest-update sha1-ctx #"Hello ")
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest-update sha1-ctx #"world!")
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest-final sha1-ctx)
 ((3)
  0
  ()
  0
  ()
  ()
  (c values c (u . #"\323Hj\351\23nxV\274B!#\205\352yp\224GX\2")))
 #""
 #"")
((define rsa-impl (get-pk 'rsa libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define privkey (generate-private-key rsa-impl '((nbits 512))))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define pubkey (pk-key->public-only-key privkey))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define sig (digest/sign privkey 'sha1 "Hello world!"))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((digest/verify pubkey 'sha1 "Hello world!" sig)
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
((digest/verify pubkey 'sha1 "Transfer $100" sig)
 ((3) 0 () 0 () () (q values #f))
 #""
 #"")
((define dgst (digest 'sha1 "Hello world!"))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define sig (pk-sign-digest privkey 'sha1 dgst))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((pk-verify-digest pubkey 'sha1 (digest 'sha1 "Hello world!") sig)
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
((pk-verify-digest pubkey 'sha1 (digest 'sha1 "Transfer $100") sig)
 ((3) 0 () 0 () () (q values #f))
 #""
 #"")
((define skey #"VeryVerySecr3t!!")
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define e-skey (pk-encrypt pubkey skey))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((pk-decrypt privkey e-skey)
 ((3) 0 () 0 () () (c values c (u . #"VeryVerySecr3t!!")))
 #""
 #"")
((define dhparams (generate-pk-parameters 'dh '((nbits 128))))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define priv1 (generate-private-key dhparams))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define priv2 (generate-private-key dhparams))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define pub1 (pk-key->public-only-key priv1))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define pub2 (pk-key->public-only-key priv2))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define shared-secret (pk-derive-secret priv1 pub2))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((equal? shared-secret (pk-derive-secret priv2 pub1))
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
((define ecparams (generate-pk-parameters 'ec '((curve "NIST P-192"))))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define priv1 (generate-private-key ecparams))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define priv2 (generate-private-key ecparams))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define pub1 (pk-key->public-only-key priv1))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define pub2 (pk-key->public-only-key priv2))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define shared-secret (pk-derive-secret priv1 pub2))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((equal? shared-secret (pk-derive-secret priv2 pub1))
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
