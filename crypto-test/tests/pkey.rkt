;; Copyright 2026 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/match
         racket/class
         racket/port
         racket/runtime-path
         crypto
         crypto/private/common/catalog
         (only-in crypto/private/common/asn1 Dss-Sig-Value)
         (only-in crypto/private/common/pk-common curve-alias->oid)
         asn1
         checkers
         (only-in "digest.rkt" all-digest-specs messages)
         "util.rkt")
(provide (all-defined-out))

(define-runtime-path kat-dir "data/")

;; test-factory-pkeys : Factory -> Void
(define (test-factory-pkeys factory)
  (test #:name "pkey"
    (for ([pkname (in-list '(rsa dsa dh ec eddsa ecx))])
      (define pk (get-pk pkname factory))
      (and pk (test-pk pkname pk)))))

;; test-pk : Symbol PKImpl -> Void
(define (test-pk pkname pk)
  (test #:name (format "~s" pkname)
    (test-pk-kat pkname pk)
    (let ([privss (make-private-keyss pkname pk)])
      (when (pk-can-encrypt? pk) (test-pk-encrypt pkname pk privss))
      (when (pk-can-key-agree? pk) (test-pk-key-agree pkname pk privss))
      (when (pk-can-sign? pk) (test-pk-sign pkname pk privss)))))

;; make-private-keyss : Symbol PKImpl -> (Listof (List PrivateKey PrivateKey))
(define (make-private-keyss pkname pk)
  (define factory (send pk get-factory))
  (case pkname
    [(rsa)
     ;; 1024-bit key is too small for PSS with SHA512
     (for/list ([nbits (in-list '(#;1024 2048 3072))])
       (for/list ([i 2]) (generate-private-key pk `((nbits ,nbits)))))]
    [(dsa)
     (if (send pk has-params?)
         (for/list ([pkpd (in-list dsa-params)])
           (define pkp (datum->pk-parameters pkpd 'rkt-params factory))
           (for/list ([i 2]) (generate-private-key pkp)))
         null)]
    [(dh)
     (if (send pk has-params?)
         (for/list ([pkpd (in-list dh-params)])
           (define pkp (datum->pk-parameters pkpd 'rkt-params factory))
           (for/list ([i 2]) (generate-private-key pkp)))
         null)]
    [(ec)
     (for/list ([curve (in-list (send factory info 'all-ec-curves))]
                #:when (not (memq curve bad-ec-curves)))
       (define pkp (generate-pk-parameters pk `((curve ,curve))))
       (for/list ([i 2]) (generate-private-key pkp)))]
    [(eddsa)
     (for/list ([curve (in-list (send factory info 'all-eddsa-curves))])
       (define pkp (generate-pk-parameters pk `((curve ,curve))))
       (for/list ([i 2]) (generate-private-key pkp)))]
    [(ecx)
     (for/list ([curve (in-list (send factory info 'all-ecx-curves))])
       (define pkp (generate-pk-parameters pk `((curve ,curve))))
       (for/list ([i 2]) (generate-private-key pkp)))]))

(define bad-ec-curves
  ;; These libcrypto curves fail sign/verify tests, maybe too short (155, 185 bits)
  '(Oakley-EC2N-3 Oakley-EC2N-4))

;; ----------------------------------------

;; test-pk-kat : PKSpec PKImpl -> Void
(define (test-pk-kat pkname pk)
  (define (kat-for-each file proc)
    (call-with-input-file (build-path kat-dir file)
      (lambda (kat-in)
        (for ([datum (in-port read kat-in)])
          (proc datum)))))
  (test #:name "KAT"
    (case pkname
      [(rsa)
       (when (send pk can-sign 'pkcs1-v1.5)
         #;
         (test #:name "signpkcs1"
           (kat-for-each "rsa-sign-pkcs1.rktd"
                         (lambda (datum) (test-rsa-sign-pkcs1-kat pk datum))))
         (test #:name "verify pkcs1 (pass/fail)"
           (kat-for-each "rsa-verify-pkcs1.rktd"
                         (lambda (datum) (test-rsa-verify-pkcs1-kat pk datum)))))
       (when (send pk can-sign 'pss*)
         (test #:name "verify pss (pass/fail)"
           (kat-for-each "rsa-verify-pss.rktd"
                         (lambda (datum) (test-rsa-verify-pss-kat pk datum)))))]
      [(dsa)
       (test #:name "verify (all valid)"
         (kat-for-each "dsa1.rktd"
                       (lambda (datum) (test-dsa1-kat pk datum))))
       (test #:name "verify (pass/fail)"
         (kat-for-each "dsa.rktd"
                       (lambda (datum) (test-dsa-kat pk datum))))]
      [(ec)
       (test #:name "ecdsa"
         (kat-for-each "ecdsa.rktd"
                       (lambda (datum) (test-ecdsa-kat pk datum))))
       (test #:name "ecdh"
         (kat-for-each "ecdh.rktd"
                       (lambda (datum) (test-ecdh-kat pk datum))))]
      [else (void)])))

(define (test-rsa-sign-pkcs1-kat pk datum)
  (void))

(define (test-rsa-verify-pkcs1-kat pk datum)
  (define factory (send pk get-factory))
  (match datum
    [`(rsa-verify-pkcs1 ((n ,n)) ,@test-data)
     (for ([test-datum (in-list test-data)])
       (match test-datum
         [`(,dspec (e ,e) (Msg ,MsgH) (S ,SH) (Result ,Result))
          (define pub (datum->pk-key `(rsa public ,n ,e) 'rkt-public factory))
          (define di (get-digest dspec factory))
          (define Msg (hex->bytes* MsgH))
          (define S (hex->bytes* SH))
          (define expect-verify? (regexp-match? #rx"^P" Result))
          (when (send pk can-sign2? 'pkcs1-v1.5 dspec)
            (check (digest/verify pub di Msg S #:pad 'pkcs1-v1.5)
                   #:is expect-verify?)
            (check (let ([dgst (digest di Msg)])
                     (pk-verify pub dgst S #:digest dspec #:pad 'pkcs1-v1.5))
                   #:is expect-verify?))]))]))

(define (test-rsa-verify-pss-kat pk datum)
  (define factory (send pk get-factory))
  (match datum
    [`(rsa-verify-pss ((n ,n) ,@_) ,@test-data)
     (for ([test-datum (in-list test-data)])
       (define (pss-test dspec e MsgH SH Result)
         (define pub (datum->pk-key `(rsa public ,n ,e) 'rkt-public factory))
         (define di (get-digest dspec factory))
         (define Msg (hex->bytes MsgH))
         (define S (hex->bytes SH))
         (define expect-verify? (regexp-match? #rx"^P" Result))
         (check (digest/verify pub di Msg S #:pad 'pss*)
                #:is expect-verify?)
         (check (let ([dgst (digest di Msg)])
                  (pk-verify pub dgst S #:digest dspec #:pad 'pss*))
                #:is expect-verify?))
       (match test-datum
         [`(,dspec (e ,e) (d ,d) (Msg ,MsgH) (S ,SH) (SaltVal ,saltH) (Result ,Result))
          (when (send pk can-sign2? 'pss* dspec)
            (pss-test dspec e MsgH SH Result))]
         [`(,dspec (e ,e) (Msg ,MsgH) (S ,SH) (Result ,Result))
          (when (send pk can-sign2? 'pss* dspec)
            (pss-test dspec e MsgH SH Result))]))]))

(define (test-dsa1-kat pk datum)
  (define factory (send pk get-factory))
  (match datum
    [`(dsa ((P ,P) (Q ,Q) (G ,G) ,dspec) ,@test-data)
     (define di (get-digest dspec factory))
     (when di
       (for ([test-datum (in-list test-data)])
         (match test-datum
           [`((Msg ,MsgH) (Y ,Y) (R ,R) (S ,S))
            (define Msg (hex->bytes MsgH))
            (define pub (datum->pk-key `(dsa public ,P ,Q ,G ,Y) 'rkt-public factory))
            (define sig (dsa-r+s->bytes R S))
            (check (digest/verify pub di Msg sig) #:is #t)
            (check (let ([dgst (digest di Msg)])
                     (pk-verify pub dgst sig #:digest dspec))
                   #:is #t)])))]))

(define (test-dsa-kat pk datum)
  (define factory (send pk get-factory))
  (match datum
    [`(dsa ((P ,P) (Q ,Q) (G ,G) ,dspec) ,@test-data)
     (define di (get-digest dspec factory))
     (when di
       (for ([test-datum (in-list test-data)])
         (match test-datum
           [`((Msg ,MsgH) (X ,X) (Y ,Y) (R ,R) (S ,S) (Result ,Result))
            (define Msg (hex->bytes* MsgH))
            (define pub (datum->pk-key `(dsa public ,P ,Q ,G ,Y) 'rkt-public factory))
            (define sig (dsa-r+s->bytes R S))
            (define expect-verify? (regexp-match? #rx"^P" Result))
            (check (digest/verify pub di Msg sig) #:is expect-verify?)
            (check (let ([dgst (digest di Msg)])
                     (pk-verify pub (digest di Msg) sig #:digest dspec))
                   #:is expect-verify?)])))]))

(define (test-ecdsa-kat pk datum)
  (define factory (send pk get-factory))
  (define factory-curves (send factory info 'all-ec-curves))
  (match datum
    [`(ecdsa ,curve ,dspec ,@test-data)
     (define curve-oid (curve-alias->oid curve))
     (define di (get-digest dspec factory))
     (when (and di (memq (alias->curve-name curve) factory-curves))
       (test #:name (format "ecdsa ~s ~s" curve dspec)
         (for ([test-datum (in-list test-data)])
           (match test-datum
             [`((Msg ,MsgH) (Qx ,QxH) (Qy ,QyH) (R ,R) (S ,S) (Result ,Result))
              (define Msg (hex->bytes* MsgH))
              (define Y (bytes-append (bytes #x04) (hex->bytes* QxH) (hex->bytes* QyH)))
              (define pub (datum->pk-key `(ec public ,curve-oid ,Y) 'rkt-public factory))
              (define sig (dsa-r+s->bytes R S))
              (define expect-verify? (regexp-match? #rx"^P" Result))
              (check (digest/verify pub di Msg sig) #:is expect-verify?)
              (check (pk-verify pub (digest di Msg) sig #:digest dspec)
                     #:is expect-verify?)]))))]))

(define (test-ecdh-kat pk datum)
  (define factory (send pk get-factory))
  (match datum
    [`(ecdh ,curve ,@test-data)
     (define curve-oid (curve-alias->oid curve))
     (test #:name (format "ecdh ~s" curve)
       (for ([test-datum (in-list test-data)])
         (match test-datum
           [`((COUNT ,c)
              (QCAVSx ,QPxH) (QCAVSy ,QPyH) (dIUT ,d) (QIUTx ,QxH) (QIUTy ,QyH)
              (ZIUT ,ZH))
            (define priv
              (let ([Q (bytes-append (bytes #x04) (hex->bytes QxH) (hex->bytes QyH))])
                (datum->pk-key `(ec private ,curve-oid ,Q ,d) 'rkt-private factory)))
            (define pub
              (let ([QP (bytes-append (bytes #x04) (hex->bytes QPxH) (hex->bytes QPyH))])
                (datum->pk-key `(ec public ,curve-oid ,QP) 'rkt-public factory)))
            (check (pk-derive-secret priv pub) #:is (hex->bytes ZH))])))]))

(define (dsa-r+s->bytes R S) ;; move to common
  (asn1->bytes/DER Dss-Sig-Value (hasheq 'r R 's S)))

(define (hex->bytes* s)
  (if (even? (string-length s))
      (hex->bytes s)
      (hex->bytes (string-append "0" s))))

;; ----------------------------------------

(define (test-pk-sign pkspec pk privss)
  (case pkspec
    [(rsa)
     ;; pkcs1, pss both need digest
     (for ([pad (in-list '(pkcs1-v1.5 pss pss*))])
       (when (send pk can-sign pad)
         (test #:name (format "sign w/ pad=~e" pad)
           (test-pk-sign/digest pk privss pad))))]
    [(dsa ec)
     ;; pad=#f, digest=#f, but apply digest
     (define pad #f)
     (test #:name (format "sign w/ pad=~e" pad)
       (test-pk-sign/digest pk privss pad))]
    [(eddsa)
     ;; pad=#f, digest=#f, apply to entire message
     (define pad #f)
     (test #:name (format "sign w/ pad=~e" pad)
       (test-pk-sign/nodigest pk privss))]))

(define (test-pk-sign/digest pk privss pad)
  (define factory (send pk get-factory))
  (for ([dspec (in-list all-digest-specs)]
        #:when (and (get-digest dspec factory)
                    (send pk can-sign2? pad dspec)))
    (test #:name (format "w/ digest=~e" dspec)
      (define di (get-digest dspec factory))
      (for ([privs (in-list privss)])
        ;; Assume priv1 != priv2
        (match-define (list priv1 priv2) privs)
        (define pub1 (pk-key->public-only-key priv1))
        (define pub2 (pk-key->public-only-key priv2))
        (test-pk-sign/digest1 priv1 pub1 priv2 pub2 pad dspec di)))))

(define (test-pk-sign/digest1 priv1 pub1 priv2 pub2 pad dspec di)
  (for ([msg (in-list sign-digest-messages)])
    (define dgst (check (digest di msg) #:values))
    (define other-msg (semirandom-bytes (bytes-length msg)))
    (define sig1 (digest/sign priv1 di msg #:pad pad))
    (define sig2 (digest/sign priv2 di msg #:pad pad))
    (define sig1* (pk-sign priv1 dgst #:pad pad #:digest dspec))
    (define sig2* (pk-sign priv2 dgst #:pad pad #:digest dspec))
    ;; Signatures are usually nondeterministic; eg, cannot expect sig1* = sig1.
    ;; But expect signatures from different keys to be different.
    (check sig1 #:is-not sig2)
    (check sig1* #:is-not sig2*)
    ;; Verify with digest/verify
    (check (digest/verify pub1 di msg sig1 #:pad pad) #:is #t)
    (check (digest/verify pub2 di msg sig2 #:pad pad) #:is #t)
    (check (digest/verify pub1 di msg sig1* #:pad pad) #:is #t)
    (check (digest/verify pub2 di msg sig2* #:pad pad) #:is #t)
    ;; Verify with pk-verify and digest
    (check (pk-verify pub1 dgst sig1 #:pad pad #:digest dspec) #:is #t)
    (check (pk-verify pub2 dgst sig2 #:pad pad #:digest dspec) #:is #t)
    (check (pk-verify pub1 dgst sig1* #:pad pad #:digest dspec) #:is #t)
    (check (pk-verify pub2 dgst sig2* #:pad pad #:digest dspec) #:is #t)
    ;; No verify mismatched sigs
    (check (digest/verify pub1 di msg sig2 #:pad pad) #:is #f)
    (check (digest/verify pub2 di msg sig1 #:pad pad) #:is #f)
    ;; No verify mismatched msgs
    (unless (equal? msg other-msg)
      (check (digest/verify pub1 di other-msg sig1 #:pad pad) #:is #f)
      (check (digest/verify pub2 di other-msg sig2 #:pad pad) #:is #f))))

(define (test-pk-sign/nodigest pk privss)
  (for ([privs (in-list privss)])
    (match-define (list priv1 priv2) privs)
    (define pub1 (pk-key->public-only-key priv1))
    (define pub2 (pk-key->public-only-key priv2))
    (test-pk-sign/nodigest1 priv1 pub1 priv2 pub2)))

(define (test-pk-sign/nodigest1 priv1 pub1 priv2 pub2)
  (for ([msg (in-list sign-nodigest-messages)])
    (define other-msg (semirandom-bytes (bytes-length msg)))
    (define sig1 (pk-sign priv1 msg))
    (define sig2 (pk-sign priv2 msg))
    (check sig1 #:is-not sig2)
    (check (pk-verify pub1 msg sig1) #:is #t)
    (check (pk-verify pub2 msg sig2) #:is #t)
    (check (pk-verify pub1 msg sig2) #:is #f)
    (check (pk-verify pub2 msg sig1) #:is #f)
    (unless (equal? msg other-msg)
      (check (pk-verify pub1 other-msg sig1) #:is #f)
      (check (pk-verify pub2 other-msg sig2) #:is #f))))

(define sign-digest-messages
  (list (semirandom-bytes 20)
        (semirandom-bytes 100)))

(define sign-nodigest-messages
  (list #;#""  ;; gcrypt can't sign empty message
        (semirandom-bytes 1)
        (semirandom-bytes 32)
        (semirandom-bytes 100)
        (semirandom-bytes 1000)))

;; ----------------------------------------

(define (test-pk-encrypt pkspec pk privss)
  (for ([pad (case pkspec [(rsa) '(pkcs1-v1.5 oaep)] [else '(#f)])])
    (when (send pk can-encrypt? pad)
      (test #:name (format "encrypt w/ pad=~e" pad)
        (for ([privs (in-list privss)])
          ;; Assume priv1 != priv2
          (match-define (list priv1 priv2) privs)
          (test-pk-encrypt1 pkspec pk priv1 priv2 pad))))))

(define (test-pk-encrypt1 pkspec pk priv1 priv2 pad)
  (define maxlen (pkey-max-encrypt-size priv1 pad))
  ;; gcrypt cannot encrypt empty message
  (for ([enclen (in-list '(#;0 7 16 19 24 32 41 56 112 128))]
        #:when (< enclen maxlen))
    (define msg (semirandom-bytes enclen))
    (define ct (pk-encrypt priv1 msg #:pad pad))
    (define pt (pk-decrypt priv1 ct #:pad pad))
    (check (pk-decrypt priv1 ct #:pad pad) #:is msg)
    (check (with-handlers ([exn:fail? (lambda (e) #f)])
             (pk-decrypt priv2 ct #:pad pad))
           #:is-not msg)))

(define (pkey-max-encrypt-size pkey pad)
  ;; FIXME: add to pk-key interface?
  ;; for now, with 1024 bits = 128 bytes... OAEP overhead is 2*hlen+2
  64)

;; ----------------------------------------

(define (test-pk-key-agree pkspec pk privss)
  (test #:name "key agreement"
    (for ([privs (in-list privss)])
      ;; Assume priv1 != priv2
      (match-define (list priv1 priv2) privs)
      (test-pk-key-agree1 pkspec pk priv1 priv2))))

(define (test-pk-key-agree1 pkspec pk priv1 priv2)
  (define pub1 (pk-key->public-only-key priv1))
  (define pub2 (pk-key->public-only-key priv2))
  (define secret1 (pk-derive-secret priv1 pub2))
  (define secret2 (pk-derive-secret priv2 pub1))
  (check secret1 #:is secret2)
  (check (pk-derive-secret priv1 pub1) #:is-not secret1)
  (check (pk-derive-secret priv2 pub2) #:is-not secret2))

;; ----------------------------------------

(define dsa-params
  '[;; DSA 1024/160
    (dsa
     params
     #xdc5bf3a88b2d99e4c95cdd7a0501cc38630d425cf5c390af3429cff1f35147b795caea923f0d3577158f8a0c89dabd1962c2c453306b5d70cacfb01430aceb54e5a5fa6f9340d3bd2da612fceeb76b0ec1ebfae635a56ab141b108e00dc76eefe2edd0c514c21c457457c39065dba9d0ecb7569c247172d8438ad2827b60435b
     #xe956602b83d195dbe945b3ac702fc61f81571f1d
     #xd7eb9ca20a3c7a079606bafc4c9261ccaba303a5dc9fe9953f197dfe548c234895baa77f441ee6a2d97b909cbbd26ff7b869d24cae51b5c6edb127a4b5d75cd8b46608bfa148249dffdb59807c5d7dde3fe3080ca3a2d28312142becb1fa8e24003e21c7287108174b95d5bc711e1c8d9b1076784f5dc37a964a5e51390da713)
    ;; DSA 2048/256
    (dsa
     params
     #xcdf428329e226cf715f18eed005e439a8c7b927edd24c866be6c1b370057059ea426d06f584f8e3c89f02fe8d4042604a2fe0db63a87ff018dfaec7790b88fd1da8396561ae62df6f18d3540992efc5ecce63068f5f595687b8bbeed5801d5b6c6bdf362dadebb80e190d719d144db693fc43cefbd72b149570a96282fd9441c397d98b15d73f8cfaa8f6514a16f5992a0a02fd7b6e4932b1e7e7ef2db717815b11e867e187aae26f9c16ca0a5ca434acf8f3356c3711765fe5e548b1edce381bdd843580f9a881d702f00a0719c3bfa8576304decb616b08ef8db6f8c3d48923a2a30b9b505ad737af1cbb0019558487400379738fd89c1ee01285e76e2d98b
     #xdaf3ebd85f57a8731538596876e8a34e73c732bc69b4d64b010bd7d5b63a09ef
     #x6cb6a8c1b8ea97173e5ae1d2a2d530468fd932b81a4f3c3e11042d56a61a504b9c207da7cdca293c04f78583cf218e1cd2c1a92637ab4ff61d2eaa5e8e8221bfe17e6a741791f21c799221ae4c703262a6dc2e295e36939e248dacaaffe673071f6dc7a90d7ca3427556fb99fb1fdca9de3f745b5e56be5b5933ebcba4f0c60fef3798cdca519997ef74acd7000d3a286d01c7000a66fe0066be4381842aa040c3bf465306c38752d41c29162c4d294f2b1f7e9ad9232aadb469047f4050b085bafa06283def7d84958528a3f129a3bc81466c0ccd493fcaa87e805e7bd4450090ce55652dba15271234fbe0cfef66f3ed9d569e565bd1218f2856637a5b26a4)])

(define dh-params
  '[;; DH 1024/160; RFC 5114 §2.1
    (dh
     params
     #xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
     #xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
     #xF518AA8781A8DF278ABA4E7D64B7CB9D49462353
     #f #f #f)
    ;; DH 2048/256; RFC 5114 §2.3
    (dh
     params
     #x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
     #x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659
     #x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3
     #f #f #f)])

;; ============================================================

(module+ main
  (require racket/cmdline crypto/all)
  (run-tests (lambda ()
               (for ([factory (in-list all-factories)])
                 (test #:name (format "~s" (send factory get-name))
                   (test-factory-pkeys factory))))
             #:progress? #t))
