;; Copyright 2013-2022 Ryan Culpepper
;; 
;; This library is free software: you can redistribute it and/or modify
;; it under the terms of the GNU Lesser General Public License as published
;; by the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.
;; 
;; This library is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU Lesser General Public License for more details.
;; 
;; You should have received a copy of the GNU Lesser General Public License
;; along with this library.  If not, see <http://www.gnu.org/licenses/>.

#lang racket/base
(require racket/class
         racket/match
         asn1
         binaryio/integer
         base64
         "catalog.rkt"
         "interfaces.rkt"
         "common.rkt"
         "error.rkt"
         "base256.rkt"
         "asn1.rkt"
         "../../util/bech32.rkt")
(provide (all-defined-out)
         curve-name->oid
         curve-alias->oid
         curve-oid->name)

;; ============================================================
;; Base classes

(define pk-impl-base%
  (class* impl-base% (pk-impl<%>)
    (inherit about get-spec get-factory)
    (super-new)
    (define/public (generate-key config)
      (cond [(has-params?)
             (define p (generate-params config))
             (send p generate-key '())]
            [else (err/no-impl this)]))
    (define/public (generate-params config)
      (crypto-error "parameters not supported\n  algorithm: ~a" (about)))

    ;; can-encrypt? : Padding -> Boolean; pad=#f means "at all?"
    (define/public (can-encrypt? pad) #f)

    ;; can-sign : Pad -> Result; pad=#f means "at all?"
    ;; Result = #f        -- not supported (eg DH)
    ;;        | 'depends  -- call can-sign2? to check specific digest arg (eg RSA)
    ;;        | 'nodigest -- supported, but digest must be 'none (eg EdDSA)
    ;;        | 'ignoredg -- supported, digest arg ignored (eg DSA, EC, for backwards-compat)
    ;; For backwards compat, want to ignore digest arg for DSA and EC; but want to forbid
    ;; for EdDSA, so that in the future giving a digest argument can mean use EdDSAph.
    (define/public (can-sign pad) #f)

    ;; can-sign2? : Pad (U DigestSpec 'none) -> Boolean
    ;; Only overridden if can-sign returned 'depends.
    (define/public (can-sign2? pad dspec) #t)

    (define/public (can-key-agree?) #f)
    (define/public (has-params?) #f)

    ;; Called by pk-read-key%; signature depends on spec
    (define/public (make-params . _) #f)
    (define/public (make-public-key . _) #f)
    (define/public (make-private-key . _) #f)
    ))

(define pk-params-base%
  (class* ctx-base% (pk-params<%>)
    (inherit-field impl)
    (super-new)
    (define/override (about) (format "~a parameters" (send impl about)))
    (abstract generate-key)
    (define/public (write-params fmt)
      (or (-write-params fmt)
          (crypto-error "parameters format not supported\n  format: ~e\n  parameters: ~a"
                        fmt (about))))
    (define/public (-write-params fmt) #f)

    (define/public (get-security-bits)
      (rkt-params-security-bits (-write-params 'rkt-params)))
    ))

(define pk-key-base%
  (class* ctx-base% (pk-key<%>)
    (inherit-field impl)
    (super-new)

    (define/override (about)
      (format "~a ~a key" (send impl about) (if (is-private?) 'private 'public)))
    (define/public (get-spec) (send impl get-spec))

    (define/public (get-security-bits)
      (if (send impl has-params?)
          (send (get-params) get-security-bits)
          #f))

    (abstract is-private?)
    (abstract get-public-key)
    (abstract equal-to-key?)

    (define/public (get-params)
      (if (send impl has-params?)
          (err/no-impl this)
          (crypto-error "key parameters not supported")))

    (define/public (write-key fmt)
      (or (-write-key fmt)
          (crypto-error "key format not supported\n  format: ~e\n  key: ~a"
                        fmt (about))))
    (define/public (-write-key fmt)
      (case fmt
        [(SubjectPublicKeyInfo rkt-public) (-write-public-key fmt)]
        [(age/v1-public)
         (match (-write-key 'rkt-public)
           [(list 'ecx 'public 'x25519 pub)
            (bech32-encode "age" pub)]
           [_ #f])]
        [(age/v1-private)
         (match (-write-key 'rkt-private)
           [(list 'ecx 'private 'x25519 pub priv)
            (string-upcase (bech32-encode "age-secret-key-" priv))]
           [_ #f])]
        [(openssh-public)
         (define (bstr bs)
           (bytes-append (integer->bytes (bytes-length bs) 4 #f) bs))
         (define (mpint n)
           (define nlen (integer-bytes-length n #t))
           (bytes-append (integer->bytes nlen 4 #f) (integer->bytes n nlen #t)))
         (match (-write-key 'rkt-public)
           [(list 'rsa 'public n e)
            (define bin (bytes-append (bstr #"ssh-rsa") (mpint e) (mpint n)))
            (format "ssh-rsa ~a" (base64-encode bin))]
           [(list 'eddsa 'public 'ed25519 pub)
            (define bin (bytes-append (bstr #"ssh-ed25519") (bstr pub)))
            (format "ssh-ed25519 ~a" (base64-encode bin))]
           [(list 'eddsa 'public 'ed448 pub)
            (define bin (bytes-append (bstr #"ssh-ed448") (bstr pub)))
            (format "ssh-ed448 ~a" (base64-encode bin))]
           [_ #f])]
        [else (if (is-private?) (-write-private-key fmt) (-write-public-key fmt))]))
    (define/public (-write-public-key fmt) #f)
    (define/public (-write-private-key fmt) #f)

    ;; ----

    (define/public (sign msg dspec0 pad)
      (define dspec (or dspec0 'none))
      (-check-sign pad dspec)
      (unless (is-private?)
        (crypto-error "signing requires private key\n  key: ~a" (about)))
      (unless (eq? dspec 'none) (-check-msg-size msg dspec))
      (-sign msg dspec pad))

    (define/public (verify msg dspec0 pad sig)
      (define dspec (or dspec0 'none))
      (-check-sign pad dspec)
      (unless (eq? dspec 'none) (-check-msg-size msg dspec))
      (-verify msg dspec pad sig))

    (define/private (-check-sign pad dspec)
      (case (send impl can-sign pad)
        [(#f)
         (unless (send impl can-sign #f)
           (crypto-error "sign/verify not supported\n  key: ~a" (about)))
         (crypto-error "sign/verify padding not supported\n  padding: ~e\n  key: ~a"
                       pad (about))]
        [(depends)
         (unless (send impl can-sign2? pad dspec)
           (crypto-error "sign/verify options not supported\n  padding: ~e\n  digest: ~e\n  key: ~a"
                         pad dspec (about)))]
        [(nodigest)
         (unless (memq dspec '(none))
           (crypto-error "sign/verify digest not supported\n  digest: ~e\n  key: ~a"
                         dspec (about)))]
        [else (void)]))

    (define/private (-check-msg-size msg dspec)
      (check-bytes-length "digest" (digest-spec-size dspec) msg
                          #:fmt "\n  digest: ~e" #:args dspec))

    (define/public (-sign msg dspec pad) (err/no-impl this))
    (define/public (-verify msg dspec pad sig) (err/no-impl this))

    ;; ----

    (define/public (encrypt buf pad)
      (-check-encrypt pad)
      (-encrypt buf pad))
    (define/public (decrypt buf pad)
      (-check-encrypt pad)
      (unless (is-private?)
        (crypto-error "decryption requires private key\n  key: ~a" (about)))
      (-decrypt buf pad))

    (define/public (compute-secret peer-pubkey)
      (-check-key-agree)
      (let ([peer-pubkey
             (cond [(pk-key? peer-pubkey) peer-pubkey]
                   [else (-convert-for-key-agree peer-pubkey)])])
        (unless (pk-key? peer-pubkey)
          (internal-error "failed to convert peer key"))
        (let ([peer-pubkey
               (cond [(eq? (send peer-pubkey get-impl) impl) peer-pubkey]
                     [else ;; public key from different impl, must convert
                      (define (bad)
                        (crypto-error "~a~a\n  peer: ~a\n  key: ~a"
                                      "peer key has different implementation"
                                      ";\n and conversion to this implementation failed"
                                      (send peer-pubkey about) (about)))
                      (define peer-pub (or (send peer-pubkey -write-key 'rkt-public) (bad)))
                      (define peer-pubkey*
                        (let* ([factory (send impl get-factory)]
                               [reader (send factory get-pk-reader)])
                          (or (send reader read-key peer-pub 'rkt-public) (bad))))
                      (unless (eq? (send peer-pubkey* get-impl) impl) (bad))
                      peer-pubkey*])])
          (unless (-compatible-for-key-agree? peer-pubkey)
            (crypto-error "peer key is not compatible\n  peer: ~a\n  key: ~a"
                          (send peer-pubkey about) (about)))
          (-compute-secret peer-pubkey))))

    (define/public (-compatible-for-key-agree? peer-pubkey)
      ;; PRE: peer-pubkey is key with same impl as this
      (err/no-impl this))

    (define/public (-convert-for-key-agree bs)
      (crypto-error "cannot convert peer public key\n  key: ~a" (about)))

    (define/private (-check-encrypt pad)
      (unless (send impl can-encrypt? #f)
        (crypto-error "encrypt/decrypt not supported\n  key: ~a" (about)))
      (unless (send impl can-encrypt? pad)
        (crypto-error "encrypt/decrypt not supported\n  padding: ~e\n  key: ~a"
                      pad (about))))

    (define/public (-encrypt buf pad) (err/no-impl this))
    (define/public (-decrypt buf pad) (err/no-impl this))

    ;; ----

    (define/private (-check-key-agree)
      (unless (send impl can-key-agree?)
        (crypto-error "key agreement not supported\n  key: ~a" (about))))

    (define/public (-compute-secret peer-pubkey)
      ;; PRE: peer-pubkey is either pk w/ same impl, or not pk (eg, bytes)
      (err/no-impl this))
    ))

;; ------------------------------------------------------------

(define pk-ec-params%
  (class pk-params-base%
    (inherit-field impl)
    (super-new)

    (abstract get-curve)

    (define/public (get-curve-oid)
      (curve-alias->oid (get-curve)))

    (define/override (-write-params fmt)
      (define curve-oid (get-curve-oid))
      (and curve-oid (encode-params-ec fmt curve-oid)))

    (define/override (generate-key config)
      (check-config config '() "EC key generation")
      (send impl generate-key-from-params this))
    ))

(define pk-eddsa-params%
  (class pk-params-base%
    (inherit-field impl)
    (init-field curve)
    (super-new)

    (define/public (get-curve) curve)

    (define/override (-write-params fmt)
      (encode-params-eddsa fmt curve))

    (define/override (generate-key config)
      (check-config config '() "EdDSA key generation")
      (send impl generate-key-from-params curve))
    ))

(define pk-ecx-params%
  (class pk-params-base%
    (inherit-field impl)
    (init-field curve)
    (super-new)

    (define/public (get-curve) curve)

    (define/override (-write-params fmt)
      (encode-params-ecx fmt curve))

    (define/override (generate-key config)
      (check-config config '() "EC/X key generation")
      (send impl generate-key-from-params curve))
    ))

;; ============================================================
;; Reading Keys

;; To avoid shared refs to mutable data:
;; - read-key makes a copy of bytestrings before forwarding them to implementations
;; - encode-*-* with 'rkt-* fmt makes a copy of bytestrings in arguments
;;   (but only for arguments where bytestring are expected)

(define public-key-formats
  '(SubjectPublicKeyInfo
    age/v1-public
    openssh-public
    rkt-public))
(define private-key-formats
  '(PrivateKeyInfo
    OneAsymmetricKey
    RSAPrivateKey
    age/v1-private
    rkt-private))

(define (public-key-format? fmt) (and (memq fmt public-key-formats) #t))
(define (private-key-format? fmt) (and (memq fmt private-key-formats) #t))

(define pk-read-key-base%
  (class* impl-base% (pk-read-key<%>)
    (inherit-field factory)
    (super-new)

    (define/public (read-key sk fmt)
      (case fmt
        [(SubjectPublicKeyInfo)
         (-check-bytes fmt sk)
         (match (bytes->asn1/DER SubjectPublicKeyInfo sk)
           ;; Note: decode w/ type checks some well-formedness properties
           [(hash-table ['algorithm alg] ['subjectPublicKey subjectPublicKey])
            (define alg-oid (hash-ref alg 'algorithm))
            (define params (hash-ref alg 'parameters #f))
            (cond [(equal? alg-oid rsaEncryption)
                   (-decode-pub-rsa subjectPublicKey)]
                  [(equal? alg-oid id-dsa)
                   (-decode-pub-dsa params subjectPublicKey)]
                  [(equal? alg-oid dhKeyAgreement)
                   (-decode-pub-dh params subjectPublicKey)]
                  [(equal? alg-oid id-ecPublicKey)
                   (-decode-pub-ec params subjectPublicKey)]
                  [(equal? alg-oid id-Ed25519)
                   (-decode-pub-eddsa 'ed25519 subjectPublicKey)]
                  [(equal? alg-oid id-Ed448)
                   (-decode-pub-eddsa 'ed448 subjectPublicKey)]
                  [(equal? alg-oid id-X25519)
                   (-decode-pub-ecx 'x25519 subjectPublicKey)]
                  [(equal? alg-oid id-X448)
                   (-decode-pub-ecx 'x448 subjectPublicKey)]
                  [else #f])]
           [_ #f])]
        [(PrivateKeyInfo OneAsymmetricKey)
         (-check-bytes fmt sk)
         (define (decode version alg privateKey publicKey)
           (define alg-oid (hash-ref alg 'algorithm))
           (define alg-params (hash-ref alg 'parameters #f))
           (cond [(equal? alg-oid rsaEncryption)
                  (-decode-priv-rsa privateKey)]
                 [(equal? alg-oid id-dsa)
                  (-decode-priv-dsa alg-params publicKey privateKey)]
                 [(equal? alg-oid dhKeyAgreement)
                  (-decode-priv-dh alg-params publicKey privateKey)]
                 [(equal? alg-oid id-ecPublicKey)
                  (-decode-priv-ec alg-params publicKey privateKey)]
                 [(equal? alg-oid id-Ed25519)
                  (-decode-priv-eddsa 'ed25519 publicKey privateKey)]
                 [(equal? alg-oid id-Ed448)
                  (-decode-priv-eddsa 'ed448 publicKey privateKey)]
                 [(equal? alg-oid id-X25519)
                  (-decode-priv-ecx 'x25519 publicKey privateKey)]
                 [(equal? alg-oid id-X448)
                  (-decode-priv-ecx 'x448 publicKey privateKey)]
                 [else #f]))
         (case fmt
           ;; Avoid attempting to parse the publicKey field (which could fail!)
           ;; unless OneAsymmetricKey is requested.
           [(PrivateKeyInfo)
            (match (bytes->asn1/DER PrivateKeyInfo sk)
              [(hash-table ['version version]
                           ['privateKeyAlgorithm alg]
                           ['privateKey privateKey])
               (decode version alg privateKey #f)]
              [_ #f])]
           [(OneAsymmetricKey)
            (match (bytes->asn1/DER OneAsymmetricKey sk)
              [(hash-table ['version version]
                           ['privateKeyAlgorithm alg]
                           ['privateKey privateKey]
                           ['publicKey publicKey])
               (decode version alg privateKey publicKey)]
              [_ #f])])]
        [(RSAPrivateKey)
         (-check-bytes fmt sk)
         (-decode-priv-rsa (bytes->asn1/DER RSAPrivateKey sk))]
        [(DSAPrivateKey)
         (-check-bytes fmt sk)
         (match (bytes->asn1/DER (SEQUENCE-OF INTEGER) sk)
           [(list 0 p q g y x) ;; FIXME!
            (-make-priv-dsa p q g y x)])]
        [(rkt-private) (read-rkt-private-key sk)]
        [(rkt-public) (read-rkt-public-key sk)]
        [(age/v1-private)
         (-check-type fmt 'bech32-string? bech32-string? sk)
         (match (bech32-decode sk)
           [(list "age-secret-key-" priv)
            (-decode-priv-ecx 'x25519 #f priv)]
           [_ #f])]
        [(age/v1-public)
         (-check-type fmt 'bech32-string? bech32-string? sk)
         (match (bech32-decode sk)
           [(list "age" pub)
            (-decode-pub-ecx 'x25519 pub)]
           [_ #f])]
        [(openssh-public)
         (-check-type fmt 'string? string? sk)
         (match (parse-openssh-pub sk)
           [(list 'rsa e n)
            (-make-pub-rsa n e)]
           [(list 'ed25519 pub)
            (-decode-pub-eddsa 'ed25519 pub)]
           [(list 'ed448 pub)
            (-decode-pub-eddsa 'ed448 pub)]
           [_ #f])]
        [else #f]))

    (define/private (read-rkt-public-key sk)
      (define nat? exact-nonnegative-integer?)
      (define (nat/f? x) (or (nat? x) (eq? x #f)))
      (define (bytes/f? x) (or (bytes? x) (eq? x #f)))
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match sk
        [(list 'rsa 'public (? nat? n) (? nat? e))
         (-make-pub-rsa n e)]
        [(list 'dsa 'public (? nat? p) (? nat? q) (? nat? g) (? nat? y))
         (-make-pub-dsa p q g y)]
        [(list 'dh 'public (? nat? p) (? nat? g) (? nat? y))
         (-make-pub-dh p g y)]
        [(list 'ec 'public (? oid? curve-oid) (? bytes? qB))
         (-make-pub-ec curve-oid (bcopy qB))]
        [(list 'eddsa 'public curve (? bytes? qB))
         (-make-pub-eddsa curve (bcopy qB))]
        [(list 'ecx 'public curve (? bytes? qB))
         (-make-pub-ecx curve (bcopy qB))]
        [_ #f]))

    (define/private (read-rkt-private-key sk)
      (define nat? exact-nonnegative-integer?)
      (define (nat/f? x) (or (nat? x) (eq? x #f)))
      (define (bytes/f? x) (or (bytes? x) (eq? x #f)))
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match sk
        [(list 'rsa 'private 0 (? nat? n) (? nat? e) (? nat? d)
               (? nat? p) (? nat? q) (? nat? dp) (? nat? dq) (? nat? qInv))
         (-make-priv-rsa n e d p q dp dq qInv)]
        [(list 'dsa 'private (? nat? p) (? nat? q) (? nat? g) (? nat/f? y) (? nat? x))
         (-make-priv-dsa p q g y x)]
        [(list 'dh 'private (? nat? p) (? nat? g) (? nat/f? y) (? nat? x))
         (-make-priv-dh p g y x)]
        [(list 'ec 'private (? oid? curve-oid) (? bytes/f? qB) (? nat? x))
         (-make-priv-ec curve-oid (bcopy qB) x)]
        [(list 'eddsa 'private (? symbol? curve) (? bytes/f? qB) (? bytes? dB))
         (-make-priv-eddsa curve (bcopy qB) (bcopy dB))]
        [(list 'ecx 'private (? symbol? curve) (? bytes/f? qB) (? bytes? dB))
         (-make-priv-ecx curve (bcopy qB) (bcopy dB))]
        [_ #f]))

    (define-syntax-rule (send-to-impl spec method arg ...)
      (let ([impl (send factory get-pk spec)])
        (and impl (send impl method arg ...))))

    ;; ---- RSA ----

    (define/public (-decode-pub-rsa subjectPublicKey)
      (match subjectPublicKey
        [(hash-table ['modulus n] ['publicExponent e])
         (-make-pub-rsa n e)]
        [_ #f]))

    (define/public (-decode-priv-rsa privateKey)
      (match privateKey
        [(hash-table ['version 0] ;; support only two-prime keys
                     ['modulus n]
                     ['publicExponent e]
                     ['privateExponent d]
                     ['prime1 p]
                     ['prime2 q]
                     ['exponent1 dp]     ;; e * dp = 1 mod (p-1)
                     ['exponent2 dq]     ;; e * dq = 1 mod (q-1)
                     ['coefficient qInv]);; q * c = 1 mod p
         (-make-priv-rsa n e d p q dp dq qInv)]
        [_ #f]))

    (define/public (-make-pub-rsa n e)
      (send-to-impl 'rsa make-public-key n e))
    (define/public (-make-priv-rsa n e d p q dp dq qInv)
      (send-to-impl 'rsa make-private-key n e d p q dp dq qInv))

    ;; ---- DSA ----

    (define/public (-decode-pub-dsa params subjectPublicKey)
      (match params
        [(hash-table ['p p] ['q q] ['g g])
         (-make-pub-dsa p q g subjectPublicKey)]
        [_ #f]))

    (define/public (-decode-priv-dsa alg-params publicKey privateKey)
      (match alg-params
        [(hash-table ['p p] ['q q] ['g g])
         (-make-priv-dsa p q g publicKey privateKey)]
        [_ #f]))

    (define/public (-make-pub-dsa p q g y)
      (send-to-impl 'dsa make-public-key p q g y))
    (define/public (-make-priv-dsa p q g y x)
      (send-to-impl 'dsa make-private-key p q g y x))

    ;; ---- DH ----

    (define/public (-decode-pub-dh params y)
      (match params
        [(hash-table ['prime p] ['base g])
         (-make-pub-dh p g y)]
        [_ #f]))

    (define/public (-decode-priv-dh params y x)
      (match params
        [(hash-table ['prime p] ['base g])
         (-make-priv-dh p g y x)]
        [_ #f]))

    (define/public (-make-pub-dh p g y)
      (send-to-impl 'dh make-public-key p g y))
    (define/public (-make-priv-dh p g y x)
      (send-to-impl 'dh make-private-key p g y x))

    ;; ---- EC ----

    (define/public (-decode-pub-ec params subjectPublicKey)
      (match params
        [`(namedCurve ,curve-oid)
         (-make-pub-ec curve-oid subjectPublicKey)]
        [_ #f]))

    (define/public (-decode-priv-ec alg-params publicKey privateKey)
      (match alg-params
        [`(namedCurve ,curve-oid)
         (match privateKey
           [(hash-table ['version 1] ['privateKey xB] ['publicKey qB])
            (-make-priv-ec curve-oid (or qB publicKey) (base256->unsigned xB))]
           [_ #f])]
        [_ #f]))

    (define/public (-make-pub-ec curve-oid qB)
      (send-to-impl 'ec make-public-key curve-oid qB))
    (define/public (-make-priv-ec curve-oid qB x)
      (send-to-impl 'ec make-private-key curve-oid qB x))

    ;; ---- EdDSA ----

    (define/public (-decode-pub-eddsa curve qB)
      (-make-pub-eddsa curve qB))
    (define/public (-decode-priv-eddsa curve qB dB)
      (-make-priv-eddsa curve qB dB))

    (define/public (-make-pub-eddsa curve qB)
      (send-to-impl 'eddsa make-public-key curve qB))
    (define/public (-make-priv-eddsa curve qB dB)
      (send-to-impl 'eddsa make-private-key curve qB dB))

    ;; ---- ECX ----

    (define/public (-decode-pub-ecx curve qB)
      (-make-pub-ecx curve qB))
    (define/public (-decode-priv-ecx curve qB dB)
      (-make-priv-ecx curve qB dB))

    (define/public (-make-pub-ecx curve qB)
      (send-to-impl 'ecx make-public-key curve qB))
    (define/public (-make-priv-ecx curve qB dB)
      (send-to-impl 'ecx make-private-key curve qB dB))

    ;; ----------------------------------------

    (define/public (read-params buf fmt)
      (case fmt
        [(AlgorithmIdentifier)
         (-check-bytes fmt buf)
         (match (ensure-keys (bytes->asn1/DER AlgorithmIdentifier/DER buf) '(parameters))
           [(hash-table ['algorithm alg-oid] ['parameters parameters])
            (cond [(equal? alg-oid id-dsa)
                   (read-params parameters 'Dss-Parms)] ;; Dss-Parms
                  [(equal? alg-oid dhKeyAgreement)
                   (read-params parameters 'DHParameter)] ;; DHParameter
                  [(equal? alg-oid id-ecPublicKey)
                   (read-params parameters 'EcpkParameters)] ;; EcpkParameters
                  [(equal? alg-oid id-Ed25519) (-make-params-eddsa 'ed25519)]
                  [(equal? alg-oid id-Ed448)   (-make-params-eddsa 'ed448)]
                  [(equal? alg-oid id-X25519)  (-make-params-ecx   'x25519)]
                  [(equal? alg-oid id-X448)    (-make-params-ecx   'x448)]
                  [else #f])]
           [_ #f])]
        [(DSAParameters Dss-Parms)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER Dss-Parms buf)
           [(hash-table ['p p] ['q q] ['g g])
            (-make-params-dsa p q g)]
           [_ #f])]
        [(DHParameter) ;; PKCS#3 ... not DomainParameters!
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER DHParameter buf)
           [(hash-table ['prime prime] ['base base])
            (-make-params-dh prime base)]
           [_ #f])]
        [(EcpkParameters)
         (-check-bytes fmt buf)
         (match (bytes->asn1/DER EcpkParameters buf)
           [(list 'namedCurve curve-oid)
            (-make-params-ec curve-oid)]
           [_ #f])]
        [(rkt-params) (read-rkt-params buf)]
        [else #f]))

    (define/private (read-rkt-params p)
      (define nat? exact-nonnegative-integer?)
      (define (oid? x) (and (list? x) (andmap nat? x)))
      (match p
        [(list 'dsa 'params (? nat? p) (? nat? q) (? nat? g))
         (-make-params-dsa p q g)]
        [(list 'dh 'params (? nat? p) (? nat? g))
         (-make-params-dh p g)]
        [(list 'ec 'params (? oid? curve-oid))
         (-make-params-ec curve-oid)]
        [(list 'eddsa 'params (? symbol? curve))
         (-make-params-eddsa curve)]
        [(list 'ecx 'params (? symbol? curve))
         (-make-params-ecx curve)]
        [_ #f]))

    (define/public (-make-params-dsa p q g)
      (send-to-impl 'dsa make-params p q g))
    (define/public (-make-params-dh p g)
      (send-to-impl 'dh make-params p g))
    (define/public (-make-params-ec curve-oid)
      (send-to-impl 'ec make-params curve-oid))
    (define/public (-make-params-eddsa curve)
      (send-to-impl 'eddsa make-params curve))
    (define/public (-make-params-ecx curve)
      (send-to-impl 'ecx make-params curve))

    ;; ----------------------------------------

    (define/private (-check-bytes fmt v)
      (-check-type fmt 'bytes? bytes? v))
    (define/private (-check-type fmt what pred v)
      (unless (pred v)
        (crypto-error "bad value for key format\n  expected: ~a\n  got: ~e\n  format: ~e"
                      what v fmt)))
    ))

(define translate-key%
  (class pk-read-key-base%
    (init-field fmt)
    (super-new (factory #f) (spec 'translate-key))
    (define/override (-make-pub-rsa n e)
      (encode-pub-rsa fmt n e))
    (define/override (-make-priv-rsa n e d p q dp dq qInv)
      (encode-priv-rsa fmt n e d p q dp dq qInv))
    (define/override (-make-params-dsa p q g)
      (encode-params-dsa fmt p q g))
    (define/override (-make-pub-dsa p q g y)
      (encode-pub-dsa fmt p q g y))
    (define/override (-make-priv-dsa p q g y x)
      (encode-priv-dsa fmt p q g y x))
    (define/override (-make-params-dh p g)
      (encode-params-dh fmt p g))
    (define/override (-make-pub-dh p g y)
      (encode-pub-dh fmt p g y))
    (define/override (-make-priv-dh p g y x)
      (encode-priv-dh fmt p g y x))
    (define/override (-make-params-ec curve-oid)
      (encode-params-ec fmt curve-oid))
    (define/override (-make-pub-ec curve-oid qB)
      (encode-pub-ec fmt curve-oid qB))
    (define/override (-make-priv-ec curve-oid qB x)
      (encode-priv-ec fmt curve-oid qB x))
    (define/override (-make-params-eddsa curve)
      (encode-params-eddsa fmt curve))
    (define/override (-make-pub-eddsa curve qB)
      (encode-pub-eddsa fmt curve qB))
    (define/override (-make-priv-eddsa curve qB dB)
      (encode-priv-eddsa fmt curve qB dB))
    (define/override (-make-params-ecx curve)
      (encode-params-ecx fmt curve))
    (define/override (-make-pub-ecx curve qB)
      (encode-pub-ecx fmt curve qB))
    (define/override (-make-priv-ecx curve qB dB)
      (encode-priv-ecx fmt curve qB dB))
    ))

;; translate-key : Datum KeyFormat KeyFormat -> (U Datum #f)
(define (translate-key key-datum from-fmt to-fmt)
  (send (new translate-key% (fmt to-fmt)) read-key key-datum from-fmt))

;; translate-params : Datum ParamsFormat ParamsFormat -> (U Datum #f)
(define (translate-params params-datum from-fmt to-fmt)
  (send (new translate-key% (fmt to-fmt)) read-params params-datum from-fmt))

;; merge-rkt-private-key : Datum Datum -> Datum
;; Try to fill missing fields in priv with pub.
(define (merge-rkt-private-key priv pub)
  (or (match priv
        [(list 'dsa 'private p q g #f x)
         (match pub
           [(list 'dsa 'public _ _ _ y)
            (list 'dsa 'private p q g y x)]
           [_ #f])]
        [(list 'dh 'private p g #f x)
         (match pub
           [(list 'dh 'public _ _ y)
            (list 'dh 'private p g y x)]
           [_ #f])]
        [(list 'ec 'private curve-oid #f d)
         (match pub
           [(list 'ec 'public _ qB)
            (list 'ec 'private curve-oid qB d)]
           [_ #f])]
        [(list 'eddsa 'private curve #f dB)
         (match pub
           [(list 'eddsa 'public _ qB)
            (list 'eddsa 'private curve qB dB)]
           [_ #f])]
        [(list 'ecx 'private curve #f dB)
         (match pub
           [(list 'ecx 'public _ qB)
            (list 'ecx 'private curve qB dB)]
           [_ #f])]
        [_ #f])
      priv))

;; bcopy : (U Bytes #f) -> (U Bytes #f)
;; Makes a fresh copy when given bytes.
(define (bcopy x) (if (bytes? x) (bytes-copy x) x))

;; check-recomputed-qB : Bytes (U Bytes #f) -> Void
(define (check-recomputed-qB new-qB maybe-old-qB)
  (when maybe-old-qB
    (unless (equal? new-qB maybe-old-qB)
      (crypto-error "public key does not match private key"))))

;; References (OpenSSH key format):
;; - https://www.thedigitalcatonline.com/blog/2018/04/25/rsa-keys/ (overview)
;; - RFC 4253 (https://datatracker.ietf.org/doc/html/rfc4253#section-6.6)
;; - RFC 8709 (for Ed{25519,448} keys)
(define (parse-openssh-pub s)
  (cond [(regexp-match #rx"^(ssh-rsa|ssh-ed25519|ssh-ed448) ([a-zA-Z0-9+/]+)(?: |$)" s)
         => (lambda (m) (parse-openssh-pub* (cadr m) (base64-decode (caddr m))))]
        [else (error 'wtf) #f]))
(define (parse-openssh-pub* outer-tag-s bin)
  (define (bad msg) (crypto-error "invalid key encoding~a" msg))
  (define binlen (bytes-length bin))
  (define (check-len n) (unless (<= n binlen) (bad " (index out of range)")))
  (define (get-uint4 n) (check-len (+ n 4)) (bytes->integer bin #f #t n (+ n 4)))
  (define (get-bstring n len) (check-len (+ n len)) (subbytes bin n (+ n len)))
  (define taglen (get-uint4 0))
  (define inner-tag (get-bstring 4 taglen))
  (unless (equal? (bytes->string/latin-1 inner-tag) outer-tag-s)
    (bad " (key type mismatch)"))
  (define keystart (+ 4 taglen))
  (case inner-tag
    [(#"ssh-rsa")
     (define elen (get-uint4 keystart))
     (define e (bytes->integer (get-bstring (+ keystart 4) elen) #t))
     (define nlen (get-uint4 (+ keystart 4 elen)))
     (define n (bytes->integer (get-bstring (+ keystart 4 elen 4) nlen) #t))
     (unless (= binlen (+ keystart 4 elen 4 nlen)) (bad " (bytes left over)"))
     (list 'rsa e n)]
    [(#"ssh-ed25519")
     (define publen (get-uint4 keystart))
     (define pub (get-bstring (+ keystart 4) publen))
     (unless (= publen 32) (bad " (wrong key length)"))
     (unless (= binlen (+ keystart 4 publen)) (bad " (bytes left over)"))
     (list 'ed25519 pub)]
    [(#"ssh-ed448")
     (define publen (get-uint4 keystart))
     (define pub (get-bstring (+ keystart 4) publen))
     (unless (= publen 57) (bad " (wrong key length)"))
     (unless (= binlen (+ keystart 4 publen)) (bad " (bytes left over)"))
     (list 'ed448 pub)]
    [else #f]))

;; ============================================================
;; Writing Keys

;; Only use OneAsymmetricKey format if public key supplied and
;; PrivateKeyInfo can't represent it.

;; On presence/absence of AlgorithmIdentifier parameters:
;; - CAB BR (v1.7.3) section 7.1.3 says for SPKI
;;   - NULL parameters must be present for RSA
;; - RFC 8410 says in general
;;   - for Ed25519 etc, parameters must be absent

(define (private-key->der fmt priv pub)
  (cond [(and (eq? fmt 'OneAsymmetricKey) pub)
         (asn1->bytes/DER OneAsymmetricKey
                          (hash-set* priv 'version 1 'publicKey pub))]
        [else
         (asn1->bytes/DER PrivateKeyInfo
                          (hash-set priv 'version 0))]))

;; ---- RSA ----

(define (encode-pub-rsa fmt n e)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      ;; CAB BR (v1.7.3) section 7.1.3.1.1 says MUST include NULL parameter
      (hasheq 'algorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
              'subjectPublicKey (hasheq 'modulus n 'publicExponent e)))]
    [(rkt-public) (list 'rsa 'public n e)]
    [else #f]))

(define (encode-priv-rsa fmt n e d p q dp dq qInv)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key fields
     (asn1->bytes/DER
      PrivateKeyInfo
      (hasheq 'version 0
              'privateKeyAlgorithm (hasheq 'algorithm rsaEncryption 'parameters #f)
              'privateKey (-priv-rsa n e d p q dp dq qInv)))]
    [(RSAPrivateKey)
     (asn1->bytes/DER RSAPrivateKey (-priv-rsa n e d p q dp dq qInv))]
    [(rkt-private) (list 'rsa 'private 0 n e d p q dp dq qInv)]
    [else (encode-pub-rsa fmt n e)]))

(define (-priv-rsa n e d p q dp dq qInv)
  (hasheq 'version 0
          'modulus n
          'publicExponent e
          'privateExponent d
          'prime1 p
          'prime2 q
          'exponent1 dp
          'exponent2 dq
          'coefficient qInv))

;; ---- DSA ----

(define (encode-params-dsa fmt p q g)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY
       (hasheq 'algorithm id-dsa 'parameters (hasheq 'p p 'q q 'g g)))]
    [(DSAParameters Dss-Parms)
     (asn1->bytes/DER Dss-Parms (hasheq 'p p 'q q 'g g))]
    [(rkt-params) (list 'dsa 'params p q g)]
    [else #f]))

(define (encode-pub-dsa fmt p q g y)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm id-dsa 'parameters (hasheq 'p p 'q q 'g g))
              'subjectPublicKey y))]
    [(rkt-public) (list 'dsa 'public p q g y)]
    [else #f]))

(define (encode-priv-dsa fmt p q g y x)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm id-dsa
                                           'parameters (hasheq 'p p 'q q 'g g))
              'privateKey x)
      y)]
    [(DSAPrivateKey)
     (asn1->bytes/DER
      (SEQUENCE-OF INTEGER)
      (list 0 p q g y x))]
    [(rkt-private) (list 'dsa 'private p q g y x)]
    [else (encode-pub-dsa fmt p q g y)]))

;; ---- DH ----

(define (encode-params-dh fmt p g)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY
       (hasheq 'algorithm dhKeyAgreement
               'parameters (hasheq 'prime p 'base g)))]
    [(DHParameter)
     (asn1->bytes/DER DHParameter
       (hasheq 'prime p 'base g))]
    [(rkt-params) (list 'dh 'params p g)]
    [else #f]))

(define (encode-pub-dh fmt p g y)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm dhKeyAgreement
                                 'parameters (hasheq 'prime p 'base g))
              'subjectPublicKey y))]
    [(rkt-public) (list 'dh 'public p g y)]
    [else #f]))

(define (encode-priv-dh fmt p g y x)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm dhKeyAgreement
                                           'parameters (hasheq 'prime p 'base g))
              'privateKey x)
      y)]
    [(rkt-private) (list 'dh 'private p g y x)]
    [else (encode-pub-dh fmt p g y)]))

;; ---- EC ----

(define (encode-params-ec fmt curve-oid)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER AlgorithmIdentifier/PUBKEY
       (hasheq 'algorithm id-ecPublicKey
               'parameters (list 'namedCurve curve-oid)))]
    [(EcpkParameters)
     (asn1->bytes/DER EcpkParameters (list 'namedCurve curve-oid))]
    [(rkt-params) (list 'ec 'params curve-oid)]
    [else #f]))

(define (encode-pub-ec fmt curve-oid qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm id-ecPublicKey
                                 'parameters (list 'namedCurve curve-oid))
              'subjectPublicKey qB))]
    [(rkt-public) (list 'ec 'public curve-oid (bcopy qB))]
    [else #f]))

(define (encode-priv-ec fmt curve-oid qB d)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     ;; OAK note: private key already contains public key
     (asn1->bytes/DER
      PrivateKeyInfo
      (hasheq 'version 0
              'privateKeyAlgorithm (hasheq 'algorithm id-ecPublicKey
                                           'parameters (list 'namedCurve curve-oid))
              'privateKey (hasheq 'version 1
                                  'privateKey (unsigned->base256 d)
                                  'publicKey qB)))]
    [(rkt-private) (list 'ec 'private curve-oid (bcopy qB) d)]
    [else (encode-pub-ec fmt curve-oid qB)]))

;; ---- EdDSA ----

(define (encode-params-eddsa fmt curve)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER
      AlgorithmIdentifier/PUBKEY
      ;; RFC 8410 says parameters MUST be absent.
      (hasheq 'algorithm (ed-curve->oid curve)))]
    [(rkt-params) (list 'eddsa 'params curve)]
    [else #f]))

(define (encode-priv-eddsa fmt curve qB dB)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm (ed-curve->oid curve))
              'privateKey dB)
      qB)]
    [(rkt-private) (list 'eddsa 'private curve (bcopy qB) (bcopy dB))]
    [else (encode-pub-eddsa fmt curve qB)]))

(define (encode-pub-eddsa fmt curve qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm (ed-curve->oid curve))
              'subjectPublicKey qB))]
    [(rkt-public) (list 'eddsa 'public curve (bcopy qB))]
    [else #f]))

(define (ed-curve->oid curve)
  (case curve
    [(ed25519) id-Ed25519]
    [(ed448)   id-Ed448]))

;; ---- ECX ----

(define (encode-params-ecx fmt curve)
  (case fmt
    [(AlgorithmIdentifier)
     (asn1->bytes/DER
      AlgorithmIdentifier/PUBKEY
      ;; RFC 8410 says parameters MUST be absent.
      (hasheq 'algorithm (x-curve->oid curve)))]
    [(rkt-params) (list 'ecx 'params curve)]
    [else #f]))

(define (encode-priv-ecx fmt curve qB dB)
  (case fmt
    [(PrivateKeyInfo OneAsymmetricKey)
     (private-key->der
      fmt
      (hasheq 'privateKeyAlgorithm (hasheq 'algorithm (x-curve->oid curve))
              'privateKey dB)
      qB)]
    [(rkt-private) (list 'ecx 'private curve (bcopy qB) (bcopy dB))]
    [else (encode-pub-ecx fmt curve qB)]))

(define (encode-pub-ecx fmt curve qB)
  (case fmt
    [(SubjectPublicKeyInfo)
     (asn1->bytes/DER
      SubjectPublicKeyInfo
      (hasheq 'algorithm (hasheq 'algorithm (x-curve->oid curve))
              'subjectPublicKey qB))]
    [(rkt-public) (list 'ecx 'public curve (bcopy qB))]
    [else #f]))

(define (x-curve->oid curve)
  (case curve
    [(x25519) id-X25519]
    [(x448)   id-X448]))

;; ============================================================

;; EC public key = ECPoint = octet string
;; EC private key = unsigned integer

;; Reference: SEC1 Section 2.3
;; We assume no compression, valid, not infinity, prime field.
;; mlen = ceil(bitlen(p) / 8), where q is the field in question.

;; ec-point->bytes : Nat Nat -> Bytes
(define (ec-point->bytes mlen x y)
  ;; no compression, assumes valid, assumes not infinity/zero point
  ;; (eprintf "encode\n mlen=~v\n x=~v\n y=~v\n" mlen x y)
  (bytes-append (bytes #x04) (integer->bytes x mlen #f #t) (integer->bytes y mlen #f #t)))

;; bytes->ec-point : Bytes -> (cons Nat Nat)
(define (bytes->ec-point buf)
  (define (bad) (crypto-error "failed to parse ECPoint"))
  (define buflen (bytes-length buf))
  (unless (> buflen 0) (bad))
  (case (bytes-ref buf 0)
    [(#x04) ;; uncompressed point
     (unless (odd? buflen) (bad))
     (define len (quotient (sub1 (bytes-length buf)) 2))
     (define x (bytes->integer buf #f #t 1 (+ 1 len)))
     (define y (bytes->integer buf #f #t (+ 1 len) (+ 1 len len)))
     ;; (eprintf "decode\n mlen=~v\n x=~v\n y=~v\n" len x y)
     (cons x y)]
    [else (bad)]))

;; curve-alias->oid : Symbol/String -> OID/#f
(define (curve-alias->oid alias)
  (curve-name->oid (alias->curve-name alias)))

;; ============================================================

(define config:rsa-keygen
  `((nbits ,exact-positive-integer? #f #:opt 2048)
    (e     ,exact-positive-integer? #f #:opt #f)))

(define config:dsa-paramgen
  `((nbits ,exact-positive-integer? "exact-positive-integer?"    #:opt 2048)
    (qbits ,(lambda (x) (member x '(160 256))) "(or/c 160 256)"  #:opt #f)))

(define config:dh-paramgen
  `((nbits     ,exact-positive-integer? #f                  #:opt 2048)
    (generator ,(lambda (x) (member x '(2 5))) "(or/c 2 5)" #:opt 2)))

(define config:ec-paramgen
  `((curve ,(lambda (x) (or (symbol? x) (string? x))) "(or/c symbol? string?)" #:req)))

(define config:eddsa-keygen
  `((curve ,(lambda (x) (memq x '(ed25519 ed448))) "(or/c 'ed25519 'ed448)" #:req)))

(define config:ecx-keygen
  `((curve ,(lambda (x) (memq x '(x25519 x448))) "(or/c 'x25519 'x448)" #:req)))

;; ============================================================
;; Security strength levels

;; Reference:
;; - NIST SP-800-57 Part 1 Section 5.6: Guidance for Cryptographic Algorithm and Key-Size...
;;   (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

;; Strength ratings: 0, 80, 112, 128, 192, 256

(define (rsa-security-bits nbits)
  (cond [(>= nbits 15360) 256]
        [(>= nbits 7680) 192]
        [(>= nbits 3072) 128]
        [(>= nbits 2048) 112]
        [(>= nbits 1024) 80]
        [else 0]))

(define (dsa/dh-security-bits nbits [qbits +inf.0])
  (cond [(and (>= nbits 3072) (>= qbits 256)) 128]
        [(and (>= nbits 2048) (>= qbits 224)) 112]
        [(and (>= nbits 1024) (>= qbits 160)) 80]
        [else 0]))

(define (ec-security-bits nbits)
  (cond [(>= nbits 512) 256]
        [(>= nbits 384) 192]
        [(>= nbits 256) 128]
        [(>= nbits 224) 112]
        [(>= nbits 160) 80]
        [else 0]))

(define (curve-security-bits curve)
  (define (ec n) (ec-security-bits n))
  (case (alias->curve-name curve)
    [(ed25519 x25519) (ec 255)]
    [(ed448 x448) (ec 448)]
    ;; -- Prime-order fields --
    [(secp192k1 secp192r1) (ec 192)]
    [(secp224k1 secp224r1) (ec 224)]
    [(secp256k1 secp256r1) (ec 256)]
    [(secp384r1) (ec 384)]
    [(secp521r1) (ec 521)]
    ;; -- Characteristic 2 fields --
    [(sect163k1 sect163r1) (ec 163)]
    [(sect163r2 sect233k1) (ec 163)]
    [(sect233r1) (ec 233)]
    [(sect239k1) (ec 239)]
    [(sect283k1 sect283r1) (ec 283)]
    [(sect409k1 sect409r1) (ec 409)]
    [(sect571k1 sect571r1) (ec 571)]
    ;; --
    [else #f]))

(define (rkt-params-security-bits params)
  (match params
    [(list 'dsa p q g) (dsa/dh-security-bits (add1 (log p 2)) (add1 (log q 2)))]
    [(list 'dh 'params p g) (dsa/dh-security-bits (add1 (log p 2)))]
    [(list 'ec 'params curve-oid)
     (curve-security-bits (curve-oid->name curve-oid))]
    [(list 'eddsa 'params curve) (curve-security-bits curve)]
    [(list 'ecx 'params curve) (curve-security-bits curve)]
    [else #f]))
