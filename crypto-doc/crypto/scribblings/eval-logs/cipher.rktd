;; This file was created by make-log-based-eval
((require crypto crypto/libcrypto)
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((crypto-factories (list libcrypto-factory))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((cipher-block-size '(aes cbc)) ((3) 0 () 0 () () (q values 16)) #"" #"")
((cipher-block-size '(aes ctr)) ((3) 0 () 0 () () (q values 1)) #"" #"")
((cipher-block-size '(salsa20 stream)) ((3) 0 () 0 () () (q values 1)) #"" #"")
((cipher-default-key-size '(aes cbc)) ((3) 0 () 0 () () (q values 16)) #"" #"")
((cipher-default-key-size '(chacha20 stream))
 ((3) 0 () 0 () () (q values 32))
 #""
 #"")
((cipher-key-sizes '(aes cbc))
 ((3) 0 () 0 () () (q values (16 24 32)))
 #""
 #"")
((cipher-key-sizes '(chacha20 stream))
 ((3) 0 () 0 () () (q values (32)))
 #""
 #"")
((cipher-iv-size '(aes cbc)) ((3) 0 () 0 () () (q values 16)) #"" #"")
((cipher-iv-size '(aes ctr)) ((3) 0 () 0 () () (q values 16)) #"" #"")
((cipher-iv-size '(aes gcm)) ((3) 0 () 0 () () (q values 12)) #"" #"")
((cipher-iv-size '(aes ecb)) ((3) 0 () 0 () () (q values 0)) #"" #"")
((cipher-iv-size '(chacha20-poly1305 stream))
 ((3) 0 () 0 () () (q values 12))
 #""
 #"")
((cipher-iv-size '(chacha20-poly1305/iv8 stream))
 ((3) 0 () 0 () () (q values 8))
 #""
 #"")
((cipher-aead? '(aes ctr)) ((3) 0 () 0 () () (q values #f)) #"" #"")
((cipher-aead? '(aes gcm)) ((3) 0 () 0 () () (q values #t)) #"" #"")
((cipher-aead? '(chacha20-poly1305 stream))
 ((3) 0 () 0 () () (q values #t))
 #""
 #"")
((cipher-default-auth-size '(aes gcm))
 ((3) 0 () 0 () () (q values 16))
 #""
 #"")
((cipher-default-auth-size '(aes ctr)) ((3) 0 () 0 () () (q values 0)) #"" #"")
((define key (generate-cipher-key '(aes ctr)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define iv (generate-cipher-iv '(aes ctr)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define ciphertext (encrypt '(aes ctr) key iv "Hello world!"))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
(ciphertext
 ((3) 0 () 0 () () (c values c (u . #"\331 >\303\0\370\240Mf\177\345\204")))
 #""
 #"")
((decrypt '(aes ctr) key iv ciphertext)
 ((3) 0 () 0 () () (c values c (u . #"Hello world!")))
 #""
 #"")
((define key (generate-cipher-key '(aes gcm)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define iv (generate-cipher-iv '(aes gcm)))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((define-values
  (ciphertext auth-tag)
  (encrypt/auth '(aes gcm) key iv "Hello world!" #:aad #"greeting"))
 ((3) 0 () 0 () () (c values c (void)))
 #""
 #"")
((decrypt/auth
  '(aes gcm)
  key
  iv
  ciphertext
  #:aad
  #"greeting"
  #:auth-tag
  auth-tag)
 ((3) 0 () 0 () () (c values c (u . #"Hello world!")))
 #""
 #"")
((decrypt/auth
  '(aes gcm)
  key
  iv
  ciphertext
  #:aad
  #"INVALID"
  #:auth-tag
  auth-tag)
 ((3) 0 () 0 () () (q exn "decrypt: authenticated decryption failed"))
 #""
 #"")
