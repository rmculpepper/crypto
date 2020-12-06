#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/class
                     racket/contract
                     crypto x509))

@title[#:tag "x509"]{X.509 Certificates}

@defmodule[x509]

@; ----------------------------------------

@defproc[(certificate? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a certificate, @racket[#f]
otherwise. Certificates implement the @racket[certificate<%>]
interface.

A @deftech{certificate} represents an assertion that a @emph{cryptographic
public key} is tied to an @emph{identity}, to be used for a particular
@emph{purpose}. The assertion is cryptographically signed by another party, the
@emph{issuer}.

For example, a web site would present a certificate with their public
key, their identity in the form of their DNS name, and the purpose of
identifying a TLS server. That certificate's issuer would own a certificate for
the purpose of acting as a @deftech{certificate authority} (CA), and its public
key should match the private key used to sign the TLS server's certificate.

One does not decide whether to trust a certificate in isolation; it depends on
whether the issuer is trusted, and that often involves obtaining a certificate
for the issuer and deciding whether to trust it, and so on. In general, trust is
evaluated for a @tech{certificate chain}; chains are built and evaluated using a
@tech{certificate store}.
}

@definterface[certificate<%> ()]{

Public interface for certificates.

Note that @racket[(certificate? _v)] implies @racket[(is-a? _v
certificate<%>)], but not vice versa. That is, a certificate object
implements additional internal interfaces not exposed to users.

@defmethod[(get-public-key) public-only-key?]{

Creates a public key from the SubjectPublicKeyInfo in the certificate
using a factory from @racket[(crypto-factories)].
}

@defmethod[(suitable-for-tls-server? [host string?]) boolean?]{

Returns @racket[#t] if the certificate is suitable for identifying a TLS server
and establishing a TLS connection, and if the certificate's subject common name
(CN) or subject alternative name (SAN) matches the given @racket[host] name;
otherwise, returns @racket[#f].
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

Certificates are delimited by @tt{----BEGIN CERTIFICATE-----} and @tt{-----END
CERTIFICATE-----} lines. Data outside of the delimiters is ignored and
discarded, so certificates may be interleaved with other text. For example,
the @exec{openssl s_client -showcerts} command logs certificates intermixed with
other diagnostic messages during TLS handshaking.
}

@defproc[(pem-file->certificates [pem-file path-string?]
                                 [#:count count (or/c exact-nonnegative-integer? +inf.0) +inf.0])
         (listof certificate?)]{

Like @racket[read-pem-certificates], but reads from the given
@racket[pem-file].
}

@; ----------------------------------------

@defproc[(certificate-chain? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a certificate chain, @racket[#f]
otherwise. Certificate chains implement the @racket[certificate-chain<%>]
interface.

A @deftech{certificate chain} contains a non-empty list of certificates,
starting with a root CA certificate and ending with the certificate whose
identity, public key, and purpose are of interest to the application. The list
of certificates satisfies the @emph{chain-validity} properties: each certificate
is the issuer of the next, each certificate in the chain has a valid signature,
and the validity period of the chain is non-empty. However,
@emph{chain-validity} is only a basic well-formedness property; it does not mean
that the end certificate is @emph{valid for a given purpose}. In particular:
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
}

@definterface[certificate-chain<%> ()]{

Public interface for certificate chains.

Note that @racket[(certificate-chain? _v)] implies @racket[(is-a? _v
certificate-chain<%>)], but not vice versa. That is, a certificate
chain object implements additional internal interfaces not exposed to
users.

@defmethod[(get-end-certificate) certificate?]{

Returns the certificate that the chain certifies.
}

@defmethod[(trusted? [store certificate-store?]
                     [from-time exact-integer? (current-seconds)]
                     [to-time exact-integer? (current-seconds)])
           boolean?]{

Returns @racket[#t] if the chain starts with a root CA certificate that is
trusted according to @racket[store] and if the validity of the chain includes
the period from @racket[from-time] to @racket[to-time]; otherwise, returns
@racket[#f].
}

@defmethod[(suitable-for-tls-server? [host string?]) boolean?]{

Returns @racket[#t] if the chain ends with a certificate that is suitable for
identifying a TLS server and matches the given @racket[host] DNS name;
otherwise, returns @racket[#f].

Equivalent to
@racketblock[
(send (send @#,(this-obj) get-end-certificate)
      suitable-for-tls-server? host)
]
}
}

@; ----------------------------------------

@defproc[(certificate-store? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] is a certificate store, @racket[#f]
otherwise. Certificate stores implement the @racket[certificate-store<%>]
interface.

A @deftech{certificate store} contains certificates for the a priori trusted
root CAs. Root CA certificates are typically self-issued and self-signed. The
store may also contain certificates that are not directly trusted, but may be
used in the construction of chains.
}

@definterface[certificate-store<%> ()]{

@defmethod[(add [#:trusted-certs trusted-certs (listof certificate?) null]
                [#:untrusted-certs untrusted-certs (listof certificate?) null])
           certificate-store?]{

Creates a new certificate store like @(this-obj) but where
@itemlist[
@item{The @racket[trusted-certs] and @racket[untrusted-certs] are available for
building certificate chains.}
@item{The @racket[trusted-certs] are considered trusted roots.}
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

Builds a certificate chain starting with some trusted root CA and ending with
@racket[end-cert]. The chain may be built from intermediate certificates from
@racket[other-untrusted-certs] in addition to the certificates already in the
store. The result chain is chain-valid; it is valid for a period including
@racket[valid-time]; and it starts with a root CA trusted by @(this-obj).

If no such chain can be constructed, an exception is raised.
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
period including @racket[valid-time]; and it starts with a root CA trusted by
@(this-obj).
}

}
