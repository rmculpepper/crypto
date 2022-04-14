#lang racket/base
(require racket/lazy-require)

(lazy-require
 [(submod "." unix) (openssl-trust-sources)]
 [(submod "." macos) (macos-trust-anchors)]
 [(submod "." windows) (win32-trust-anchors)])

(provide openssl-trust-sources
         macos-trust-anchors
         win32-trust-anchors)

;; ============================================================
;; Unix (OpenSSL) trust anchors

;; Based on openssl/mzssl

(module unix racket/base
  (require racket/list
           ffi/unsafe
           ffi/unsafe/define
           crypto/private/libcrypto/ffi)
  (provide openssl-trust-sources)

  ;; References:
  ;; - https://bugzilla.redhat.com/show_bug.cgi?id=1053882
  ;; - https://www.happyassassin.net/posts/2015/01/12/a-note-about-ssltls-trusted-certificate-stores-and-platforms/ (2015)
  ;; - https://github.com/openSUSE/ca-certificates

  ;; A directory is considered an OpenSSL hashed cert dir if it exists and
  ;; has at least one file (symlink?) of the form "[[:xdigit:]]{8}.0".
  (define (ok-cert-dir? dir)
    (and (directory-exists? dir)
         (for/or ([file (in-list (directory-list dir))])
           (define filepath (build-path dir file))
           (and (or (link-exists? filepath)
                    (file-exists? filepath))
                (regexp-match? #px"^[[:xdigit:]]{8}[.]0$" file)))))

  (define (ok-cert-file? file)
    (and (file-exists? file)))

  (define-crypto X509_get_default_cert_dir  (_fun -> _string))
  (define-crypto X509_get_default_cert_file (_fun -> _string))
  (define-crypto X509_get_default_cert_dir_env (_fun -> _string))
  (define-crypto X509_get_default_cert_file_env (_fun -> _string))

  ;; openssl-trust-sources : Symbol -> (values (Listof Path) (Listof Path))
  (define (openssl-trust-sources who)
    (unless libcrypto
      (error who "libcrypto not available"))
    ;; Workaround for natipkg openssl library: the default cert locations vary
    ;; from distro to distro, and there is no one configuration that works with
    ;; all. So build natipkg libssl.so with `--openssldir="/RACKET_USE_ALT_PATH"`
    ;; and this code will override with better guesses.
    (define alt-dirs '("/etc/ssl/certs"))
    (define alt-files '("/etc/ssl/certs/ca-certificates.crt"
                        "/etc/ssl/certs/ca-bundle.crt"))
    (define (use-alt-path? p) (regexp-match? #rx"^/RACKET_USE_ALT_PATH" p))
    (define (subst-cert-dir p) (if (use-alt-path? p) alt-dirs p))
    (define (subst-cert-file p) (if (use-alt-path? p) alt-files p))
    ;; ----
    (define cert-dirs0
      (or (getenv (X509_get_default_cert_dir_env)) (X509_get_default_cert_dir)))
    (define cert-file0
      (or (getenv (X509_get_default_cert_file_env)) (X509_get_default_cert_file)))
    ;; Use path-string? filter to avoid {file,directory}-exists? error on "".
    (define cert-dirs
      (let ([cert-dirs1 (path-list-string->path-list cert-dirs0 null)])
        (filter path-string? (flatten (map subst-cert-dir cert-dirs1)))))
    (define cert-files
      (filter path-string? (flatten (map subst-cert-file (list cert-file0)))))
    (values (filter ok-cert-dir? cert-dirs)
            (filter ok-cert-file? cert-files))))


;; ============================================================
;; Mac OS trust anchors

(module macos racket/base
  (require ffi/unsafe
           ffi/unsafe/objc
           ffi/unsafe/define)
  (provide macos-trust-anchors)

  ;; TO DO:
  ;; - better error handling
  ;; - reliable mem management
  ;; - alternatives to deprecated functions

  ;; Alternative: generate PEM file with
  ;; security export -k /System/Library/Keychains/... -t certs -f pemseq -o foo.pem

  ;; ----------------------------------------
  ;; CoreFoundation FFI

  (define libcf
    (case (system-type 'os*)
      [(macosx darwin)
       (ffi-lib "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")]
      [else #f]))

  (define-ffi-definer define-cf libcf
    #:default-make-fail make-not-available)

  (define _fourchar _uint32)
  (define _OSStatus _sint32)
  (define _CFIndex _slong)

  (define-cpointer-type _CFDataRef)

  (define-cf CFRelease (_fun _pointer -> _void))

  (define-cf CFDataGetLength
    (_fun _CFDataRef -> _CFIndex))

  (define-cf CFDataGetBytePtr
    (_fun _CFDataRef -> _pointer))

  (define (CFData->bytes data)
    (let* ([len (CFDataGetLength data)]
           [buf (make-bytes len)]
           [data-ptr (CFDataGetBytePtr data)])
      (memcpy buf data-ptr len)
      buf))

  (define-cpointer-type _CFArrayRef)

  (define-cf CFArrayGetCount
    (_fun [theArray : _CFArrayRef]
          -> _CFIndex))

  (define-cf CFArrayGetValueAtIndex
    (_fun [theArray : _CFArrayRef]
          [idx : _CFIndex]
          -> _pointer))

  ;; ----------------------------------------
  ;; Security FFI

  (define libsec
    (case (system-type 'os*)
      [(macosx darwin) (ffi-lib "/System/Library/Frameworks/Security.framework/Security")]
      [else #f]))
  (define-ffi-definer define-sec libsec
    #:default-make-fail make-not-available)

  (define kSecFormatX509Cert 9)
  (define _SecExternalFormat _int)

  (define item-export-type
    (_fun (item) ::
          (item : _id)  ;; FIXME: SecCertificateRef or array
          (_SecExternalFormat = kSecFormatX509Cert) ;; DER
          (_int = 0)
          (_pointer = #f)
          (ref : (_ptr o _CFDataRef))
          -> (result : _OSStatus)
          -> (values result ref)))

  (define-sec SecKeychainItemExport #| deprecated in 10.7 |# item-export-type)
  (define-sec SecItemExport #|since 10.7|# item-export-type
    #:fail (lambda () SecKeychainItemExport))

  (define-sec SecTrustCopyAnchorCertificates
    (_fun [anchors : (_ptr o _CFArrayRef)]
          -> (status : _OSStatus)
          -> (values status anchors)))

  ;; ----------------------------------------

  (define (macos-trust-anchors who)
    (define-values (status roots) (SecTrustCopyAnchorCertificates))
    (unless (= 0 status)
      (error who "unable to retrieve Mac OS trust anchors (error ~s)" status))
    (define len (CFArrayGetCount roots))
    (begin0 (for/list ([i (in-range len)])
              (define cert (CFArrayGetValueAtIndex roots i))
              (cert->der (cast cert _pointer _id)))
      (CFRelease roots)))

  (define (cert->der item)
    (define-values (status data) (SecItemExport item))
    (begin0 (CFData->bytes data)
      (CFRelease data))))


;; ============================================================
;; Windows trust anchors

;; Based on openssl/private/win32.

(module windows racket/base
  (require ffi/unsafe
           ffi/unsafe/define
           ffi/unsafe/alloc
           ffi/winapi)
  (provide win32-trust-anchors)

  ;; -- Windows CryptoAPI
  (define crypt-lib
    (case (system-type)
      ((windows) (ffi-lib "crypt32.dll"))
      (else #f)))
  (define-ffi-definer define-crypt crypt-lib
    #:default-make-fail make-not-available)

  (define _DWORD _int32)
  (define-cpointer-type _CERTSTORE)
  (define-cstruct _sCERT_CONTEXT
    ([certEncodingType _int32]
     [certEncoded _pointer]
     [certEncodedLen _int32]
     [certInfo _pointer]
     [certStore _pointer]))
  (define-cpointer-type _CERT_CONTEXT _sCERT_CONTEXT-pointer)

  (define-crypt CertCloseStore
    (_fun #:abi winapi
          _CERTSTORE
          (_DWORD = 0)
          -> _int)
    #:wrap (deallocator))
  (define-crypt CertOpenSystemStoreW
    (_fun #:abi winapi #:save-errno 'windows
          (_pointer = #f)
          _string/utf-16
          -> _CERTSTORE/null)
    #:wrap (allocator CertCloseStore))
  (define-crypt CertEnumCertificatesInStore
    (_fun #:abi winapi
          _CERTSTORE
          _CERT_CONTEXT/null
          -> _CERT_CONTEXT/null))

  (define (CERT_CONTEXT->x509-bytes c)
    (let* ([len (sCERT_CONTEXT-certEncodedLen c)]
           [data (sCERT_CONTEXT-certEncoded c)]
           [buf (make-bytes len)])
      (memcpy buf data len)
      buf))

  ;; win32-trust-anchors : Symbol String -> (Listof Bytes)
  (define (win32-trust-anchors who [storename "ROOT"])
    (define cstore (CertOpenSystemStoreW storename))
    (unless cstore
      (error who "failed to open certificate store (error=~s)\n  store: ~e"
             (saved-errno) storename))
    (let loop ([curr-c #f] [acc null])
      (cond [(CertEnumCertificatesInStore cstore curr-c)
             => (lambda (c)
                  (define x509-bytes (CERT_CONTEXT->x509-bytes c))
                  (loop c (cons x509-bytes acc)))]
            [else
             (CertCloseStore cstore)
             (reverse acc)]))))
