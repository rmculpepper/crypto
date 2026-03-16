;; Copyright 2013-2018 Ryan Culpepper
;; SPDX-License-Identifier: Apache-2.0

#lang racket/base
(require racket/class
         racket/match
         ffi/unsafe
         asn1
         "../common/catalog.rkt"
         "../common/common.rkt"
         "../common/pk-common.rkt"
         "../common/error.rkt"
         "../common/base256.rkt"
         "ffi.rkt")
(provide (all-defined-out))

(define DSA-Sig-Val (SEQUENCE [r INTEGER] [s INTEGER]))

(define (int->mpi n)   (base256->mpi (unsigned->base256 n)))
(define (mpi->int mpi) (base256->unsigned (mpi->base256 mpi)))

(define (sexp-get-mpi outersexp outertag tag)
  (define sexp (gcry_sexp_find_token outersexp outertag))
  (define tag-sexp (gcry_sexp_find_token sexp tag))
  (gcry_sexp_nth_mpi tag-sexp 1))
(define (sexp-get-data outersexp outertag tag)
  (define sexp (gcry_sexp_find_token outersexp outertag))
  (define tag-sexp (gcry_sexp_find_token sexp tag))
  (gcry_sexp_nth_data tag-sexp 1))
(define (sexp-get-int outersexp outertag tag)
  (mpi->int (sexp-get-mpi outersexp outertag tag)))

(define gcrypt-read-key%
  (class pk-read-key-base%
    (inherit-field factory)
    (super-new (spec 'gcrypt-read-key))))

;; ============================================================

(define gcrypt-pk-impl%
  (class pk-impl-base%
    (inherit-field factory)
    (super-new)

    (define/public (-generate-keypair keygen-sexp)
      (define result
        (or (gcry_pk_genkey keygen-sexp)
            (crypto-error "failed to generate key")))
      (define pub
        (or (gcry_sexp_find_token result "public-key")
            (crypto-error "failed to generate public key component")))
      (define priv
        (or (gcry_sexp_find_token result "private-key")
            (crypto-error "failed to generate private key component")))
      (values pub priv))
    ))

(define gcrypt-pk-key%
  (class pk-key-base%
    (init-field pub priv)
    (inherit-field impl)
    (super-new)

    (define/override (is-private?) (and priv #t))

    (define/override (get-public-key)
      (if priv (new this% (impl impl) (pub pub) (priv #f)) this))

    (define/override (equal-to-key? other)
      (and (is-a? other gcrypt-pk-key%)
           (let ([d1 (send this write-key 'rkt-public)]
                 [d2 (send other write-key 'rkt-public)])
             (and d1 d2 (equal? d1 d2)))))

    (define/override (-sign digest digest-spec pad)
      (check-sig-pad pad)
      (define data-sexp (sign-make-data-sexp digest digest-spec pad))
      (define sig-sexp (gcry_pk_sign data-sexp priv))
      (define result (sign-unpack-sig-sexp sig-sexp))
      (gcry_sexp_release sig-sexp)
      (gcry_sexp_release data-sexp)
      result)

    (define/override (-verify digest digest-spec pad sig)
      (check-sig-pad pad)
      (define data-sexp (sign-make-data-sexp digest digest-spec pad))
      (define sig-sexp (verify-make-sig-sexp sig))
      (define result (and sig-sexp (gcry_pk_verify sig-sexp data-sexp pub)))
      (when sig-sexp (gcry_sexp_release sig-sexp))
      (gcry_sexp_release data-sexp)
      result)

    (abstract sign-make-data-sexp
              sign-unpack-sig-sexp
              verify-make-sig-sexp
              check-sig-pad)
    ))

;; ============================================================

(define gcrypt-rsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'rsa))

    (define/override (can-encrypt? pad) (and (memq pad '(#f pkcs1-v1.5 oaep)) #t))
    (define/override (can-sign pad)
      ;; Before 1.8, can't set salt for PSS.
      (define ok-pads (if v1.8/later? '(#f pkcs1-v1.5 pss) '(#f pkcs1-v1.5)))
      (and (memq pad ok-pads) 'ignoredg))
    (define/override (can-sign2? pad dspec)
      ;; Sign/verify fails on some digests (eg, blake2*, sha512/256), not clear
      ;; how to pre-check (gcry_md_get_asnoid not helpful).
      (and (memq dspec '(sha1 sha224 sha256 sha384 sha512 md5
                              sha3-224 sha3-256 sha3-384 sha3-512))
           (send factory get-digest dspec) #t))

    (define/override (generate-key config)
      (define-values (nbits e)
        (check/ref-config '(nbits e) config config:rsa-keygen "RSA key generation"))
      (let (;; e default 0 means use gcrypt default "secure and fast value"
            [e (or e 0)])
        (define-values (pub priv)
          (-generate-keypair
           (make-sexp `(genkey (rsa (nbits ,nbits) (rsa-use-e ,e))))))
        (new gcrypt-rsa-key% (impl this) (pub pub) (priv priv))))

    ;; ----

    (define/override (make-public-key n e)
      (define pub (make-rsa-public-key n e))
      (new gcrypt-rsa-key% (impl this) (pub pub) (priv #f)))

    (define/private (make-rsa-public-key n e)
      (make-sexp `(public-key (rsa (n ,(unsigned->base256 n))
                                   (e ,(unsigned->base256 e))))))

    (define/override (make-private-key n e d p0 q0 dp dq qInv)
      ;; gcrypto requires p < q; simpler to just always recompute u
      (define-values (p q) (if (< p0 q0) (values p0 q0) (values q0 p0)))
      (define u-mpi (gcry_mpi_new))
      (unless (gcry_mpi_invm u-mpi (int->mpi p) (int->mpi q))
        (internal-error "failed to calculate qInv"))
      (define u (mpi->int u-mpi))
      (define pub (make-rsa-public-key n e))
      (define priv (make-rsa-private-key n e d p q u))
      (new gcrypt-rsa-key% (impl this) (pub pub) (priv priv)))

    (define/private (make-rsa-private-key n e d p q u)
      (define priv
        (make-sexp `(private-key (rsa (n ,(unsigned->base256 n))
                                      (e ,(unsigned->base256 e))
                                      (d ,(unsigned->base256 d))
                                      (p ,(unsigned->base256 p))
                                      (q ,(unsigned->base256 q))
                                      (u ,(unsigned->base256 u))))))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-rsa-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-security-bits)
      (rsa-security-bits (gcry_pk_get_nbits pub)))

    (define/override (-write-private-key fmt)
      (define (get-mpi tag) (sexp-get-mpi priv "rsa" tag))
      (define n-mpi (get-mpi "n"))
      (define e-mpi (get-mpi "e"))
      (define d-mpi (get-mpi "d"))
      (define p-mpi (get-mpi "p"))
      (define q-mpi (get-mpi "q"))
      (define tmp (gcry_mpi_new))
      (define dp-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp p-mpi 1)
      (or (gcry_mpi_invm dp-mpi e-mpi tmp)
          (internal-error "failed to calculate dP"))
      (define dq-mpi (gcry_mpi_new))
      (gcry_mpi_sub_ui tmp q-mpi 1)
      (or (gcry_mpi_invm dq-mpi e-mpi tmp)
          (internal-error "failed to calculate dQ"))
      (define qInv-mpi (gcry_mpi_new))
      (or (gcry_mpi_invm qInv-mpi p-mpi q-mpi)
          (internal-error "failed to calculate qInv"))
      (apply encode-priv-rsa fmt
             (map mpi->int (list n-mpi e-mpi d-mpi p-mpi q-mpi dp-mpi dq-mpi qInv-mpi))))

    (define/override (-write-public-key fmt)
      (define (get-int tag) (sexp-get-int pub "rsa" tag))
      (encode-pub-rsa fmt (get-int "n") (get-int "e")))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      (define padding (check-sig-pad pad))
      (case pad
        [(pss)
         (make-sexp `(data (flags pss)
                           (salt-length ,(digest-spec-size digest-spec))
                           (hash ,digest-spec ,digest)))]
        [else
         (make-sexp `(data (flags ,padding)
                           (hash ,digest-spec ,digest)))]))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (define sig-part (gcry_sexp_find_token sig-sexp "rsa"))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      sig-data)

    (define/override (check-sig-pad pad)
      (case pad
        [(pss) #"pss"]
        [(pkcs1-v1.5 #f) #"pkcs1"]
        [else (err/bad-signature-pad impl pad)]))

    (define/override (verify-make-sig-sexp sig)
      (make-sexp `(sig-val (rsa (s ,sig)))))

    (define/override (-encrypt data pad)
      (when (zero? (bytes-length data))
        ;; gcrypt cannot encrypt the empty message, because
        ;; it does notallow empty octet strings in sexps
        (crypto-error "encryption failed (empty message)"))
      (define padding (check-enc-padding pad))
      (define data-sexp (make-sexp `(data (flags ,padding) (value ,data))))
      (define enc-sexp (gcry_pk_encrypt data-sexp pub))
      (define enc-part (gcry_sexp_find_token enc-sexp "rsa"))
      (define enc-a-part (gcry_sexp_find_token enc-part "a"))
      (define enc-mpi (gcry_sexp_nth_mpi enc-a-part 1))
      (define enc-data (mpi->base256 enc-mpi))
      (gcry_mpi_release enc-mpi)
      (gcry_sexp_release enc-a-part)
      (gcry_sexp_release enc-part)
      (gcry_sexp_release enc-sexp)
      (gcry_sexp_release data-sexp)
      enc-data)

    (define/override (-decrypt data pad)
      (define padding (check-enc-padding pad))
      (define enc-sexp (make-sexp `(enc-val (flags ,padding) (rsa (a ,data)))))
      (define dec-sexp
        (or (gcry_pk_decrypt enc-sexp priv)
            (crypto-error "decryption failed")))
      (define dec-data (gcry_sexp_nth_data dec-sexp 1))
      (gcry_sexp_release enc-sexp)
      (gcry_sexp_release dec-sexp)
      dec-data)

    (define/private (check-enc-padding pad)
      (case pad
        [(#f oaep) #"oaep"]
        [(pkcs1-v1.5) #"pkcs1"]
        [else (err/bad-encrypt-pad impl pad)]))
    ))


;; ============================================================

;; TODO: implement DSA param support

(define gcrypt-dsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'dsa))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'ignoredg))

    (define/override (generate-key config)
      (define-values (nbits qbits)
        (check/ref-config '(nbits qbits) config config:dsa-paramgen "DSA parameters generation"))
      (let ([qbits (or qbits 256)])
        (define-values (pub priv)
          (-generate-keypair
           (make-sexp `(genkey (dsa (nbits ,nbits) (qbits ,qbits))))))
        (new gcrypt-dsa-key% (impl this) (pub pub) (priv priv))))

    ;; ----

    (define/override (make-public-key p q g y)
      (define pub (make-dsa-public-key p q g y))
      (new gcrypt-dsa-key% (impl this) (pub pub) (priv #f)))

    (define/private (make-dsa-public-key p q g y)
      (make-sexp `(public-key (dsa (p ,(unsigned->base256 p))
                                   (q ,(unsigned->base256 q))
                                   (g ,(unsigned->base256 g))
                                   (y ,(unsigned->base256 y))))))

    (define/override (make-private-key p q g y0 x)
      (define y  ;; g^x mod p
        (or y0
            (let ([y (gcry_mpi_new)])
              (gcry_mpi_powm y (int->mpi g) (int->mpi x) (int->mpi p))
              (mpi->int y))))
      (define pub (make-dsa-public-key p q g y))
      (define priv (make-dsa-private-key p q g y x))
      (define impl (send factory get-pk 'dsa))
      (new gcrypt-dsa-key% (impl this) (pub pub) (priv priv)))

    (define/private (make-dsa-private-key p q g y x)
      (define priv
        (make-sexp `(private-key (dsa (p ,(unsigned->base256 p))
                                      (q ,(unsigned->base256 q))
                                      (g ,(unsigned->base256 g))
                                      (y ,(unsigned->base256 y))
                                      (x ,(unsigned->base256 x))))))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-dsa-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-security-bits)
      (dsa/dh-security-bits (gcry_pk_get_nbits pub)))

    (define/override (-write-private-key fmt)
      (define (get-int tag) (sexp-get-int priv "dsa" tag))
      (apply encode-priv-dsa fmt (map get-int '("p" "q" "g" "y" "x"))))

    (define/override (-write-public-key fmt)
      (define (get-int tag) (sexp-get-int pub "dsa" tag))
      (apply encode-pub-dsa fmt (map get-int '("p" "q" "g" "y"))))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      ;; When the digest is larger than qbits, it must be truncated,
      ;; but gcrypt cannot truncate externally-created digest.
      (define qbits (integer-length (sexp-get-int pub "dsa" "q")))
      (define digest* (if (> (* 8 (bytes-length digest)) qbits)
                          (subbytes digest 0 (quotient (+ qbits 7) 8))
                          digest))
      (make-sexp `(data (flags raw) (value ,digest*))))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "dsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

    (define/override (verify-make-sig-sexp sig-der)
      (match (with-handlers ([exn:fail:asn1? void])
               (bytes->asn1/DER DSA-Sig-Val sig-der))
        [(hash-table ['r (? exact-nonnegative-integer? r)]
                     ['s (? exact-nonnegative-integer? s)])
         (make-sexp `(sig-val (dsa (r ,(unsigned->base256 r))
                                   (s ,(unsigned->base256 s)))))]
        [_ #f]))
    ))

(define (unpack-sig-sexp sig-sexp label)
  (define sig-part (gcry_sexp_find_token sig-sexp label))
  (define sig-r-part (gcry_sexp_find_token sig-part "r"))
  (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
  (define sig-s-part (gcry_sexp_find_token sig-part "s"))
  (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
  (gcry_sexp_release sig-r-part)
  (gcry_sexp_release sig-s-part)
  (gcry_sexp_release sig-part)
  (asn1->bytes/DER DSA-Sig-Val
                   (hasheq 'r (base256->unsigned sig-r-data)
                           's (base256->unsigned sig-s-data))))

;; ============================================================

(define gcrypt-ec-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'ec))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'ignoredg))
    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ec-paramgen "EC parameter generation")
      (define curve (config-ref config 'curve))
      (curve->params curve))

    (define/public (curve->params curve)
      (define curve* (alias->curve-name curve))
      (unless (memq curve* gcrypt-curves)
        (err/no-curve curve this))
      (new gcrypt-ec-params% (impl this) (curve curve*)))

    (define/public (generate-key-from-params params)
      (define curve (send params get-curve))
      (define-values (pub priv)
        (-generate-keypair
         (make-sexp `(genkey (ecc (curve ,curve))))))
      (new gcrypt-ec-key% (impl this) (pub pub) (priv priv)))

    ;; ----

    (define/override (make-params curve-oid)
      (curve->params (curve-oid->name curve-oid)))

    (define/override (make-public-key curve-oid qB)
      (cond [(curve-oid->name-string curve-oid)
             => (lambda (curve-name)
                  (check-ec-q curve-name qB)
                  (define pub (make-ec-public-key curve-name qB))
                  (new gcrypt-ec-key% (impl this) (pub pub) (priv #f)))]
            [else #f]))

    (define/private (make-ec-public-key curve qB)
      (make-sexp `(public-key (ecc (curve ,curve) (q ,qB)))))

    (define/override (make-private-key curve-oid qB d)
      (cond [(curve-oid->name-string curve-oid)
             => (lambda (curve-name)
                  (define qB* (recompute-ec-q curve-name d))
                  (when qB (check-recomputed-qB qB* qB))
                  (define pub (make-ec-public-key curve-name qB*))
                  (define priv (make-ec-private-key curve-name qB* d))
                  (new gcrypt-ec-key% (impl this) (pub pub) (priv priv)))]
            [else #f]))

    (define/private (make-ec-private-key curve qB d)
      (define priv
        (make-sexp `(private-key (ecc (curve ,curve)
                                      (q ,qB)
                                      (d ,(unsigned->base256 d))))))
      (gcry_pk_testkey priv)
      priv)

    (define/private (check-ec-q curve-name qB)
      (when decode-point-ok?
        (define ec (gcry_mpi_ec_new curve-name))
        (define qpoint (gcry_mpi_point_new))
        (gcry_mpi_ec_decode_point qpoint (base256->mpi qB) ec)
        (begin0 (unless (gcry_mpi_ec_curve_point qpoint ec)
                  (err/off-curve "public key"))
          (gcry_ctx_release ec)
          (gcry_mpi_point_release qpoint))))

    (define/private (recompute-ec-q curve-name d)
      (define ec (gcry_mpi_ec_new curve-name))
      (gcry_mpi_ec_set_mpi 'd (int->mpi d) ec)
      (define pub-sexp (gcry_pubkey_get_sexp GCRY_PK_GET_PUBKEY ec))
      (begin0 (sexp-get-data pub-sexp "ecc" "q")
        (gcry_sexp_release pub-sexp)
        (gcry_ctx_release ec)))

    (define/private (curve-oid->name-string oid)
      (define name-sym (curve-oid->name oid))
      (and (memq name-sym gcrypt-curves)
           (string->bytes/latin-1 (symbol->string name-sym))))
    ))

(define gcrypt-ec-params%
  (class pk-ec-params%
    (init-field curve)
    (super-new)
    (define/override (get-curve) curve)
    ))

(define gcrypt-ec-key%
  (class gcrypt-pk-key%
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (new gcrypt-ec-params% (impl impl) (curve (get-curve))))

    (define/override (-write-private-key fmt)
      (define curve-oid (get-curve-oid priv))
      (and curve-oid
           (let ([qB (sexp-get-data priv "ecc" "q")]
                 [d (sexp-get-int priv "ecc" "d")])
             (encode-priv-ec fmt curve-oid qB d))))

    (define/override (-write-public-key fmt)
      (define curve-oid (get-curve-oid pub))
      (and curve-oid
           (let ([qB (sexp-get-data pub "ecc" "q")])
             (encode-pub-ec fmt curve-oid qB))))

    (define/public (get-curve [sexp pub])
      (string->symbol (bytes->string/utf-8 (sexp-get-data sexp "ecc" "curve"))))
    (define/public (get-curve-oid [sexp pub])
      (curve-alias->oid (get-curve sexp)))

    (define/override (sign-make-data-sexp digest digest-spec pad)
      ;; When the digest is larger than the bits of the EC field, it must be
      ;; truncated, but gcrypt cannot truncate externally-created digest.
      ;; (See comment before _gcry_dsa_normalize_hash in libgcrypt source.)
      (define qbits (gcry_pk_get_nbits pub))
      (define digest* (if (> (* 8 (bytes-length digest)) qbits)
                          (subbytes digest 0 (quotient (+ qbits 7) 8))
                          digest))
      (make-sexp `(data (flags raw) (value ,digest*))))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (unpack-sig-sexp sig-sexp "ecdsa"))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

    (define/override (verify-make-sig-sexp sig-der)
      (match (with-handlers ([exn:fail:asn1? void])
               (bytes->asn1/DER DSA-Sig-Val sig-der))
        [(hash-table ['r (? exact-nonnegative-integer? r)]
                     ['s (? exact-nonnegative-integer? s)])
         (make-sexp `(sig-val (ecdsa (r ,(unsigned->base256 r))
                                     (s ,(unsigned->base256 s)))))]
        [_ #f]))

    ;; ECDH support is not documented, but described in comments in
    ;; libgcrypt/cipher/ecc.c before ecc_{encrypt,decrypt}_raw.
    (define/override (-compute-secret peer-pubkey)
      (define peer (sexp-get-data (get-field pub peer-pubkey) "ecc" "q"))
      (define dh-sexp (make-sexp `(enc-val (ecdh (e ,peer)))))
      (define sh (gcry_pk_decrypt dh-sexp priv))
      (define shb (gcry_sexp_nth_data sh 1))
      ;; shb is an EC point; decode and extract the x-coordinate
      ;; cf (unsigned->base256 (car (bytes->ec-point shb)))
      (define shblen (bytes-length shb))
      (subbytes shb 1 (+ 1 (quotient shblen 2))))

    (define/override (-compatible-for-key-agree? peer-pubkey)
      (equal? (get-curve-oid) (send peer-pubkey get-curve-oid)))

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key (get-curve-oid) bs))
    ))

;; ============================================================

(define gcrypt-eddsa-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'eddsa))

    (define/override (can-sign pad) (and (memq pad '(#f)) 'nodigest))
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:eddsa-keygen "EdDSA parameter generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (unless (check-curve curve) (err/no-curve curve this))
      (new pk-eddsa-params% (impl this) (curve curve)))

    (define/public (generate-key-from-params curve)
      (define curve-name (or (check-curve curve) (err/no-curve curve this)))
      (define-values (pub priv)
        (-generate-keypair
         (make-sexp `(genkey (ecc (curve ,curve-name) (flags eddsa))))))
      (new gcrypt-eddsa-key% (impl this) (curve curve) (pub pub) (priv priv)))

    (define/private (check-curve curve)
      (case curve
        [(ed25519) (and ed25519-ok? "Ed25519")]
        [(ed448) (and ed448-ok? "Ed448")]
        [else #f]))

    ;; ----

    (define/override (make-params curve)
      (and (check-curve curve) (curve->params curve)))

    (define/override (make-public-key curve qB)
      (define (make-key pub)
        (new gcrypt-eddsa-key% (impl this) (curve curve) (pub pub) (priv #f)))
      (define curve-name (check-curve curve))
      (and curve-name (make-key (make-public-sexp curve-name qB))))

    (define/private (make-public-sexp curve-name qB)
      (make-sexp `(public-key (ecc (curve ,curve-name) (flags eddsa) (q ,qB)))))

    (define/override (make-private-key curve qB dB)
      (define (make-key pub priv)
        (new gcrypt-eddsa-key% (impl this) (curve curve) (pub pub) (priv priv)))
      (define curve-name (check-curve curve))
      ;; It doesn't seem to be possible to recover qB if missing, so just fail.
      (and curve-name qB
           (make-key (make-public-sexp curve-name qB)
                     (make-private-sexp curve-name qB dB))))

    (define/private (make-private-sexp curve-name qB dB)
      (define priv
        (make-sexp `(private-key (ecc (curve ,curve-name)
                                      (flags eddsa)
                                      (q ,qB)
                                      (d ,dB)))))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-eddsa-key%
  (class gcrypt-pk-key%
    (init-field curve)
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (send impl curve->params curve))

    (define/override (get-public-key)
      (if priv (new this% (impl impl) (curve curve) (pub pub) (priv #f)) this))

    (define/override (-write-private-key fmt)
      (let ([qB (sexp-get-data priv "ecc" "q")]
            [dB (sexp-get-data priv "ecc" "d")])
        (encode-priv-eddsa fmt curve qB dB)))

    (define/override (-write-public-key fmt)
      (let ([qB (sexp-get-data pub "ecc" "q")])
        (encode-pub-eddsa fmt curve qB)))

    (define/override (sign-make-data-sexp msg _dspec pad)
      ;; No (hash-algo sha512); wrong for Ed448, unnecessary for Ed25519 (tested 1.9.4).
      (make-sexp `(data (flags eddsa) (value ,msg))))

    (define/override (sign-unpack-sig-sexp sig-sexp)
      (define PARTLEN (case curve [(ed25519) 32] [(ed448) 57]))
      (define sig-part (gcry_sexp_find_token sig-sexp "eddsa"))
      (define sig-r-part (gcry_sexp_find_token sig-part "r"))
      (define sig-r-data (gcry_sexp_nth_data sig-r-part 1))
      (define sig-s-part (gcry_sexp_find_token sig-part "s"))
      (define sig-s-data (gcry_sexp_nth_data sig-s-part 1))
      (gcry_sexp_release sig-r-part)
      (gcry_sexp_release sig-s-part)
      (gcry_sexp_release sig-part)
      (unless (and (= PARTLEN (bytes-length sig-r-data))
                   (= PARTLEN (bytes-length sig-s-data)))
        (crypto-error "failed; implementation returned ill-formed result"))
      (bytes-append sig-r-data sig-s-data))

    (define/override (check-sig-pad pad)
      (unless (member pad '(#f))
        (err/bad-signature-pad impl pad)))

    (define/override (verify-make-sig-sexp sig-bytes)
      (define PARTLEN (case curve [(ed25519) 32] [(ed448) 57]))
      (define SIGLEN (* 2 PARTLEN))
      (and (= (bytes-length sig-bytes) SIGLEN)
           (make-sexp `(sig-val (eddsa (r ,(subbytes sig-bytes 0 PARTLEN))
                                       (s ,(subbytes sig-bytes PARTLEN SIGLEN)))))))
    ))

;; ============================================================

(define gcrypt-ecx-impl%
  (class gcrypt-pk-impl%
    (inherit-field spec factory)
    (inherit -generate-keypair)
    (super-new (spec 'ecx))

    (define/override (can-key-agree?) #t)
    (define/override (has-params?) #t)

    (define/override (generate-params config)
      (check-config config config:ecx-keygen "EC/X parameter generation")
      (curve->params (config-ref config 'curve)))

    (define/public (curve->params curve)
      (unless (check-curve curve) (err/no-curve curve this))
      (new pk-ecx-params% (impl this) (curve curve)))

    (define/public (generate-key-from-params curve)
      (define curve-name (or (check-curve curve) (err/no-curve curve this)))
      (define-values (pub priv)
        (-generate-keypair (make-sexp `(genkey (ecdh (curve ,curve-name))))))
      (new gcrypt-ecx-key% (impl this) (curve curve) (pub pub) (priv priv)))

    (define/private (check-curve curve)
      (case curve
        [(x25519) (and ed25519-ok? "Curve25519")]
        [(x448) (and ed448-ok? "X448")]
        [else #f]))

    ;; ----

    (define/override (make-params curve)
      (and (check-curve curve) (curve->params curve)))

    (define/override (make-public-key curve qB)
      (define (make-key pub)
        (new gcrypt-ecx-key% (impl this) (curve curve) (pub pub) (priv #f)))
      (define curve-name (check-curve curve))
      (and curve-name (make-key (make-public-sexp curve-name (import-q curve qB)))))

    (define/private (make-public-sexp curve-name qB)
      (make-sexp `(public-key (ecc (curve ,curve-name) (q ,qB)))))

    (define/private (import-q curve qB)
      (case curve [(x25519) (raw->ec-point qB)] [(x448) qB]))

    (define/override (make-private-key curve qB dB)
      (define (make-key pub priv)
        (new gcrypt-ecx-key% (impl this) (curve curve) (pub pub) (priv priv)))
      (define curve-name (check-curve curve))
      ;; FIXME: recover q if publicKey field not present
      (and curve-name qB
           (let ([qB (import-q curve qB)])
             (make-key (make-public-sexp curve-name qB)
                       (make-private-sexp curve-name qB dB)))))

    (define/private (make-private-sexp curve-name qB dB)
      (define priv (make-sexp `(private-key (ecc (curve ,curve-name) (q ,qB) (d ,dB)))))
      (gcry_pk_testkey priv)
      priv)
    ))

(define gcrypt-ecx-key%
  (class gcrypt-pk-key%
    (init-field curve)
    (inherit-field pub priv impl)
    (inherit is-private?)
    (super-new)

    (define/override (get-params)
      (send impl curve->params curve))

    (define/override (get-public-key)
      (if priv (new this% (impl impl) (curve curve) (pub pub) (priv #f)) this))

    (define/override (-write-private-key fmt)
      (let ([qB (sexp-get-data priv "ecc" "q")]
            [dB (sexp-get-data priv "ecc" "d")])
        (encode-priv-ecx fmt curve (export-q qB) dB)))

    (define/override (-write-public-key fmt)
      (let ([qB (sexp-get-data pub "ecc" "q")])
        (encode-pub-ecx fmt curve (export-q qB))))

    (define/private (export-q qB)
      (case curve [(x25519) (ec-point->raw qB)] [(x448) qB]))

    ;; ECDH support is not documented, but described in comments in
    ;; libgcrypt/cipher/ecc.c before ecc_{encrypt,decrypt}_raw.
    (define/override (-compute-secret peer-pubkey)
      (define peer (sexp-get-data (get-field pub peer-pubkey) "ecc" "q"))
      (define dh-sexp (make-sexp `(enc-val (ecdh (e ,peer)))))
      (define sh (gcry_pk_decrypt dh-sexp priv))
      (define shb (gcry_sexp_nth_data sh 1))
      (case curve
        [(x25519)
         ;; shb is (bytes #x40) + shared-secret; #x40 indicates Montgomery
         ;; point (x-coord only), cf _gcry_ecc_mont_decodepoint
         (unless (and (= (bytes-length shb) 33) (= (bytes-ref shb 0) #x40))
           (crypto-error "failed; implementation returned ill-formed result"))
         (subbytes shb 1)]
        [(x448)
         (unless (= (bytes-length shb) 56)
           (crypto-error "failed; implementation returned ill-formed result"))
         shb]))

    (define/override (-compatible-for-key-agree? peer-pubkey)
      #t)

    (define/override (-convert-for-key-agree bs)
      (send impl make-public-key curve bs))

    (define/override (sign-make-data-sexp) #f)
    (define/override (sign-unpack-sig-sexp) #f)
    (define/override (verify-make-sig-sexp) #f)
    (define/override (check-sig-pad) #f)
    ))

(define (ec-point->raw b)
  (unless (and (> (bytes-length b) 0) (= (bytes-ref b 0) #x40))
    (crypto-error "internal error; expected encoded Montgomery EC point"))
  (subbytes b 1))

(define (raw->ec-point b)
  (bytes-append (bytes #x40) b))
