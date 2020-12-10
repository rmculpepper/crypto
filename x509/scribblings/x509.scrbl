#lang scribble/doc
@(require scribble/manual
          scribble/basic
          scribble/example
          racket/list
          racket/runtime-path
          crypto/private/common/catalog
          (for-label racket/base
                     racket/class
                     racket/contract
                     crypto crypto/libcrypto x509))

@(define-runtime-path log-file "eval-logs/x509.rktd")
@(define-runtime-path racket-pem-file "eval-logs/racket.pem")
@(define the-eval (make-log-based-eval log-file 'replay))
@(the-eval '(require racket/class crypto crypto/libcrypto x509))
@(the-eval '(crypto-factories libcrypto-factory))

@title[#:tag "x509"]{X.509 Certificates}

@defmodule[x509]

This library provides support for X.509 certificates, specifically the profiles
and interpretations defined by @cite["PKIX"] and the
@hyperlink["https://cabforum.org/"]{CA/Browser Forum's}
@hyperlink["https://cabforum.org/baseline-requirements/"]{Baseline
Requirements}.

Note that @racketmodname[x509] is provided by the @tt{x509-lib}
package, not @tt{crypto-lib}.

@section[#:tag "cert-intro"]{Introduction to Using Certificates}

The following example shows how to configure a @tech{certificate store} with
trusted root certificates, load a PEM file to create a @tech{certificate chain},
and check whether the chain is suitable for identifying a TLS server.

First, let's use @exec{openssl s_client} to connect to
@url{https://www.racket-lang.org} and save the @tech{certificates} that the
server sends in the TLS handshake:

@verbatim{
openssl s_client -connect www.racket-lang.org:443 -showcerts \
  < /dev/null > racket.pem
}

@(the-eval `(define racket-pem-file ,(path->string racket-pem-file)))

In general, the saved file will contain one or more PEM-encapsulated
@tt{CERTIFICATE} blocks: one for the server, and zero or more intermediate CA
certificates necessary for building a @tech{certificate chain} anchored by a
trusted root CA.

If we try to load the PEM file using an empty @tech{certificate store}, we get
an error, because the store has no trusted roots:
@examples[#:eval the-eval #:label #f
(eval:alts (send (empty-certificate-store) pem-file->chain "racket.pem")
           (eval:error (send (empty-certificate-store) pem-file->chain racket-pem-file)))
]
We must configure a @tech{certificate store} with a reasonable set of trusted
roots. We must also enable some crypto factories so that the store can verify
certificate signatures.
@examples[#:eval the-eval #:label #f
(define store
  (send (empty-certificate-store) add-trusted-from-openssl-directory
        "/etc/ssl/certs"))
(crypto-factories libcrypto-factory)
]

Now we can create a certificate chain from the saved PEM file:
@examples[#:eval the-eval #:label #f
(eval:alts (define racket-chain (send store pem-file->chain "racket.pem"))
           (define racket-chain (send store pem-file->chain racket-pem-file)))
]
We can extract the chain's end certificate; we can also extract all of the
certificates in the chain:
@examples[#:eval the-eval #:label #f
(send racket-chain get-certificate)
(send racket-chain get-certificates)
]

We check whether the certificate (more precisely, the certificate
chain) is suitable for identifying a TLS server---and specifically,
@racket["www.racket-lang.org"]:
@examples[#:eval the-eval #:label #f
(send racket-chain suitable-for-tls-server? "www.racket-lang.org")
(send racket-chain suitable-for-tls-server? "www.scheme.com")
]

Finally, we can extract the end certificate's public key:
@examples[#:eval the-eval #:label #f
(define racket-pk (send racket-chain get-public-key))
]

@; ----------------------------------------
@section[#:tag "certificate"]{Certificates}

A @deftech{certificate} represents an assertion that a @emph{cryptographic
public key} is tied to an @emph{identity}, to be used for a particular
@emph{purpose}. The assertion is cryptographically signed by another party, the
@emph{issuer}.

For example, a secure web site (serving HTTP over TLS) would present a
certificate with their public key, their identity in the form of their DNS name,
and the purpose of identifying a TLS server. That certificate's issuer would own
a certificate for the purpose of acting as a @emph{certificate authority} (CA),
and its public key should verify the signature on the TLS server's certificate.

One does not decide whether to trust a certificate in isolation; it depends on
whether the issuer is trusted, and that often involves obtaining a certificate
for the issuer and deciding whether to trust it, and so on. In general, trust is
evaluated for a @tech{certificate chain}; chains are built and evaluated using a
@tech{certificate store}.

@defproc[(certificate? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a certificate, @racket[#f]
otherwise. Certificates implement the @racket[certificate<%>]
interface.
}

@definterface[certificate<%> ()]{

Public interface for certificates.

Note that @racket[(certificate? _v)] implies @racket[(is-a? _v
certificate<%>)], but not vice versa. That is, a certificate object
implements additional internal interfaces not exposed to users.

@examples[#:eval the-eval #:label #f
(define racket-cert (send racket-chain get-certificate))
racket-cert
]

Two certificates are @racket[equal?] if they have the same DER encodings.

@defmethod[(get-subject) any/c]{

Returns the @tt{Name} of the certificate's subject.

The result is a X.509 @tt{Name} value represented according to the rules of the
@racketmodname[asn1] library. See @cite["PKIX"] for the definition of @tt{Name}.

@examples[#:eval the-eval #:label #f
(send racket-cert get-subject)
]
}

@defmethod[(get-issuer) any/c]{

Returns the @tt{Name} of the certificate's issuer.

@examples[#:eval the-eval #:label #f
(send racket-cert get-issuer)
]
}

@defmethod[(get-subject-common-names) (listof string?)]{

Returns a list of Common Names (CN) occuring in the certificate's subject. A
typical certificate has at most one Common Name.

@examples[#:eval the-eval #:label #f
(send racket-cert get-subject-common-names)
]
}

@defmethod[(get-subject-alt-names [kind (or/c #f symbol?) #f]) (listof any/c)]

Returns a list of the certificate's Subject Alternative Names (SAN).

If @racket[kind] is a symbol, only subject alternative names of the given kind
are returned, and they are returned untagged. If @racket[kind] is @racket[#f],
then all SAN entries are returned, and each entry is tagged with a kind symbol
(the symbol identifies the variant of the X.509 @tt{GeneralName} type).

@examples[#:eval the-eval #:label #f
(send racket-cert get-subject-alt-names)
(send racket-cert get-subject-alt-names 'dNSName)
]

@defmethod[(get-validity-seconds) (list/c exact-integer? exact-integer?)]{

Returns the validity period of the certificate (from @tt{notBefore} to
@tt{notAfter}) in seconds (see @racket[current-seconds], @racket[seconds->date],
etc).

@examples[#:eval the-eval #:label #f
(send racket-cert get-validity-seconds)
]
}

@defmethod[(get-der) bytes?]{

Gets the DER encoding of the certificate.
}
}

@defproc[(bytes->certificate [bs bytes?]) certificate?]{

Parses @racket[bs] as a certificate. The byte string @racket[bs] must contain
exactly one DER-encoded certificate; otherwise, an exception is raised.
}

@defproc[(read-pem-certificates [in input-port?]
                                [#:count count (or/c exact-nonnegative-integer? +inf.0) +inf.0])
         (listof certificate?)]{

Reads up to @racket[count] certificates from @racket[in]. The certificates must
be encoded in the RFC 7468 textual format @cite["RFC7468"]. (This format is often
conflated with ``PEM'', although technically the two formats are not completely
compatible.)

Certificates are delimited by @racket["----BEGIN CERTIFICATE-----"] and
@racket["-----END CERTIFICATE-----"] lines. Data outside of the delimiters is
ignored and discarded, so certificates may be interleaved with other text. For
example, the @exec{openssl s_client -showcerts} command logs certificates
intermixed with other diagnostic messages during TLS handshaking.
}

@defproc[(pem-file->certificates [pem-file path-string?]
                                 [#:count count (or/c exact-nonnegative-integer? +inf.0) +inf.0])
         (listof certificate?)]{

Like @racket[read-pem-certificates], but reads from the given
@racket[pem-file].
}

@; ----------------------------------------
@section[#:tag "chains"]{Certificate Chains}

A @deftech{certificate chain} contains a non-empty list of certificates,
starting with a @deftech{trust anchor} (typically a root CA certificate) and
ending with the certificate whose identity, public key, and purpose are of
interest to the application. The list of certificates satisfies the
@emph{chain-validity} properties:
@itemlist[

@item{Each certificate is the issuer of the next---that is, the subject name of
each certificate ``matches'' @cite["PKIX"] the issuer name of the next
certificate.}

@item{Each certificate that acts as an issuer (that is, every certificate in the
chain except possibly for the final certificate) is suitable as a CA
certificate.}

@item{Each certificate's public key verifies the signature of the next
certificate in the chain. (Note that the trust anchor certificate's signature is
not checked; its trust is determined by the certificate store.)}

@item{The validity period of the chain is non-empty. The validity period of the
chain is the intersection of the validity periods of all of the certificates in
the chain. The certificates are not required to have strictly nested validity
periods.}

]
However, @emph{chain-validity} is only a basic well-formedness property; it does
not mean that the end certificate is @emph{valid for a given purpose}. In
particular:
@itemlist[

@item{A chain does not necessarily start with a trusted root CA.}
@item{A chain is not necessarily valid at the current time.}
@item{A chain's end certificate is not necessarily valid for a given purpose
(for example, for identifying particular a TLS server and creating a TLS
connection).}

]
Use @method[certificate-chain<%> trusted?] to verify the first two properties
and @method[certificate-chain<%> suitable-for-tls-server?] to verify the third
property (in the case of a TLS server).

Note: @cite["PKIX"] uses the term ``certification path'' instead of
``certificate chain''.

@defproc[(certificate-chain? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a certificate chain, @racket[#f]
otherwise. Certificate chains implement the @racket[certificate-chain<%>]
interface.
}

@definterface[certificate-chain<%> ()]{

Public interface for certificate chains.

Note that @racket[(certificate-chain? _v)] implies @racket[(is-a? _v
certificate-chain<%>)], but not vice versa. That is, a certificate
chain object implements additional internal interfaces not exposed to
users.

@defmethod[(get-certificate) certificate?]{

Returns the certificate that the chain certifies.
}

@defmethod[(get-certificates) (listof certificate?)]{

Returns all of the certificates in @(this-obj), starting with the end
certificate and ending with the @tech{trust anchor} (that is, most-specific
first).
}

@defmethod[(get-public-key) public-only-key?]{

Creates a public key from the SubjectPublicKeyInfo in the certificate
using a factory from @racket[(crypto-factories)].
}

@defmethod[(trusted? [store certificate-store?]
                     [from-time exact-integer? (current-seconds)]
                     [to-time exact-integer? from-time])
           boolean?]{

Returns @racket[#t] if the chain's @tech{trust anchor} certificate is trusted
according to @racket[store] and if the validity of the chain includes the period
from @racket[from-time] to @racket[to-time]; otherwise, returns @racket[#f].
}

@defmethod[(get-issuer-chain) (or/c certificate-chain? #f)]{

Returns the tail of the certificate chain corresponding to this certificate's
issuer, or @racket[#f] if the current certificate is the @emph{trust anchor}.
}

@defmethod[(get-subject) any/c]{

Equivalent to
@racketblock[
(send (send #,(this-obj) #,(method certificate-chain<%> get-certificate)) #,(method certificate<%> get-subject))
]
}

@defmethod[(get-subject-alt-names [kind (or/c symbol? #f) #f]) (listof any/c)]{

Equivalent to
@racketblock[
(send (send #,(this-obj) #,(method certificate-chain<%> get-certificate))
      #,(method certificate<%> get-subject-alt-names) kind)
]}

@defmethod[(suitable-for-tls-server? [host (or/c string? #f)]) boolean?]{

Returns @racket[#t] if the chain ends with a certificate that is suitable for
identifying a TLS server, and if the certificate has a subject alternative name
(SAN) that matches the given @racket[host] DNS name; otherwise, returns
@racket[#f]. If @racket[host] is @racket[#f], the DNS name check is omitted.
}

@defmethod[(suitable-for-tls-client? [name any/c]) boolean?]{

Returns @racket[#t] if the chain's certificate is suitable for identifying a
client to a TLS server, and if the certificate has a subject name or subject
alternative name (SAN) that matches the given @racket[name]; otherwise, returns
@racket[#f]. If @racket[name] is @racket[#f], then the name check is omitted.
}
}

@; ----------------------------------------
@section[#:tag "certificate-stores"]{Certificate Stores}

A @deftech{certificate store} determines which certificates are trusted a
priori---usually, these trusted certificates correspond to root CAs, which are
typically self-issued and self-signed. In this context, ``trusted'' means that
the assertion that the certificate represents (binding a public key to
identities and purposes) is accepted at face value; it does not mean that the
certificate is automatically accepted as suitable for every purpose.

The store may also contain certificates that are not directly trusted, but may
be used in the construction of chains.

@defproc[(certificate-store? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] is a certificate store, @racket[#f]
otherwise. Certificate stores implement the @racket[certificate-store<%>]
interface.
}

@defproc[(empty-certificate-store) certificate-store?]{

Returns a certificate store containing no certificates (trusted or untrusted).
}

@definterface[certificate-store<%> ()]{

Public interface for certificate stores.

Note that @racket[(certificate-store? _v)] implies @racket[(is-a? _v
certificate-store<%>)], but not vice versa. That is, a certificate
store object implements additional internal interfaces not exposed to
users.

@defmethod[(add [#:trusted-certs trusted-certs (listof certificate?) null]
                [#:untrusted-certs untrusted-certs (listof certificate?) null])
           certificate-store?]{

Creates a new certificate store like @(this-obj) but where
@itemlist[
@item{The @racket[trusted-certs] and @racket[untrusted-certs] are available for
building certificate chains.}
@item{The @racket[trusted-certs] are considered trusted.}
]
Note: trust is monotonic. That is, if a certificate is already trusted, then
adding it again as an untrusted certificate does not make it untrusted.
}

@defmethod[(add-trusted-from-pem-file [pem-file path-string?])
           certificate-store?]{

Creates a new certificate store like @(this-obj), but trusting the certificates
contained in PEM format in @racket[pem-file].
}

@defmethod[(add-trusted-from-openssl-directory [dir path-string?])
           certificate-store?]{

Creates a new certificate store like @(this-obj), but trusting the certificates
in @racket[dir], which uses OpenSSL-style hashing.
}

@defmethod[(build-chain [end-cert certificate?]
                        [other-untrusted-certs (listof certificate?) null]
                        [valid-time exact-integer? (current-seconds)])
           certificate-chain?]{

Builds a certificate chain starting with some trusted certificate and ending
with @racket[end-cert]. The chain may be built from intermediate certificates
from @racket[other-untrusted-certs] in addition to the certificates already in
the store. The result chain is chain-valid; it is valid for a period including
@racket[valid-time]; and its anchor is trusted by @(this-obj).

If no such chain can be constructed, an exception is raised. If multiple chains
can be constructed, one is selected, but there are no guarantees about how it is
selected.
}

@defmethod[(build-chains [end-cert certificate?]
                         [other-untrusted-certs (listof certificate?) null]
                         [valid-time exact-integer? (current-seconds)]
                         [#:empty-ok? empty-ok? boolean? #f])
           (listof certificate-chain?)]{

Like @method[certificate-store<%> build-chain], but returns all chains that
could be constructed. If no such chains can be constructed, an exception is
raised, unless @racket[empty-ok?] is true, in which case @racket[null] is
returned.
}

@defmethod[(pem-file->chain [pem-file path-string?]
                            [valid-time exact-integer? (current-seconds)])
           certificate-chain?]{

Returns a certificate chain for the @emph{first} certificate in PEM format in
@racket[pem-file], using any remaining certificates in the file as other
untrusted certificates. The result chain is chain-valid; it is valid for a
period including @racket[valid-time]; and its anchor is trusted by @(this-obj).
}

}

@; ----------------------------------------
@section[#:tag "cert-revocation"]{Certificate Revocation Checking}
@section-index["CRL" "OCSP"]

There are two main @deftech{certificate revocation} mechanisms: CRLs
(Certificate Revocation Lists) and OCSP (Online Certificate Status Protocol).

@examples[#:eval the-eval
(define rev (make-revocation-checker "/tmp/rev.db" #:fetch-crl? #f))
(send rev check-ocsp racket-chain)
(send rev check-crl racket-chain)
]

@defproc[(make-revocation-checker [db-file path-string?]
                                  [#:trust-db? trust-db? boolean? #t]
                                  [#:fetch-ocsp? fetch-ocsp? boolean? #t]
                                  [#:fetch-crl? fetch-crl? boolean? #t])
         (is-a?/c revocation-checker<%>)]{

Returns an object for performing certificate revocation checks using OCSP and
CRLs.

The @racket[db-file] is a SQLite3 database file used to cache OCSP and CRL
responses. These responses carry signatures, so they can cached even if the
cache is untrusted. (When the cache contains a response, the response is
re-verified, and if verification fails then the cached response is discarded and
a new response is retrieved.)

If @racket[trust-db?] is @racket[#t], then status information about individual
certificates is also cached. This saves parsing and signature verification time,
but these individual status records do not carry signatures, so they cannot be
re-verified later. If @racket[trust-db?] is @racket[#f], then only the
re-verifiable parts of the cache are used.

If @racket[fetch-ocsp?] is @racket[#t], then if the cache does not contain a
trusted, unexpired OCSP response, a response is fetched from the OCSP responder
URL (or URLs) in the certificate being checked. If @racket[fetch-ocsp?] is
@racket[#f], no new response is fetched; if a suitable response is not in the
cache, the certificate's status is unknown. Likewise, the @racket[fetch-crl?]
option controls requests for CRLs.
}

@definterface[revocation-checker<%> ()]{

Public interface for checking revocation of certificates.

Both the @method[revocation-checker<%> check-ocsp] and
@method[revocation-checker<%> check-crl] methods take certificate chains rather
than certificates, because verifying revocation responses requires the public
key of the certificate's issuer. Both methods check only the final certificate
in the chain for revocation.

@defmethod[(check-ocsp [chain certificate-chain?]) list?]{

Returns @racket['()] to indicate success (at least one OCSP response indicated
that the certificate is good) or a non-empty list to indicate failure or another
condition. If the list is non-empty, it will contain at least one of the
following symbols:
@itemlist[

@item{@racket['revoked] --- The certificate is revoked.}

@item{@racket['no-sources] --- The certificate's status is unknown because the
certificate listed no usable OCSP responder URLs. (This library uses only URLS
with the scheme @racket["http"] or @racket["https"].)}

@item{@racket['unknown] --- The certificate's status is unknown, either because
no responder produced a valid response, or because the response indicated that
the responder does not know the certificate's status.}

]
}

@defmethod[(check-crl [chain certificate-chain?]) list?]{

Returns @racket['()] to indicate success (at least one CRL was found and the
certificate of @racket[chain] was absent from its revocation list) or a
non-empty list to indicate failure or another condition. If the list is
non-empty, it will contain at least one of the following symbols:
@itemlist[

@item{@racket['revoked] --- The certificate is revoked.}

@item{@racket['no-sources] --- The certificate does not list any usable CRL
URLs. (This library only uses URLs with the scheme @racket["http"] or
@racket["https"].)}

@item{@racket['unavailable] --- The certificate listed a CRL URL whose content
was unavailable, either because retrieving it failed (perhaps due to a network
failure or server problem), or the retrieved CRL had a bad signature, or
@(this-obj) was configured not to fetch CRLs (and it was not in the cache).}

]
}
}

@(close-eval the-eval)
