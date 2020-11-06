#lang scribble/doc
@(require scribble/manual
          scribble/basic
          racket/list
          crypto/private/common/catalog
          (for-label racket/base
                     racket/contract
                     crypto x509))

@title[#:tag "x509"]{X.509 Certificates}

@defmodule[x509]

A @deftech{certificate} is an assertion that a @emph{cryptographic
public key} is tied to an @emph{identity}, to be used for a particular
@emph{purpose}. The assertion is signed by another party.

For example, a web site would present a certificate with their public
key, their identity in the form of the DNS name, and the purpose of
identifying a TLS server.

The trustworthiness of a certificate cannot be evaluated in isolation;
it depends on whether the certificate is signed by a trusted
@deftech{certificate authority} (CA). Determining whether to trust the
signing CA, in turn, may require inspecting its certificate, and so
on. Thus trust depends on a @deftech{certificate chain} leading to the
@deftech{end certificate} and starting with a @deftech{root
certificate}, which is trusted a priori.

A @deftech{certificate store} contains certificates for the a priori
trusted root CAs. It may also contain certificates that are not
directly trusted, but may be used in the construction of chains.

@; ----------------------------------------

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

@defmethod[(get-public-key) public-only-key?]{

Creates a public key from the SubjectPublicKeyInfo in the certificate
using a factory from @racket[(crypto-factories)].
}

@defmethod[(suitable-for-tls-server [host string?]) boolean?]{

Returns @racket[#t] if the certificate is suitable for identifying a TLS server
and establishing a TLS connection, and if the certificate's subject common name
(CN) or subject alternative name (SAN) matches the given @racket[host] name;
otherwise, returns @racket[#f].
}

}

@; ----------------------------------------

@defproc[(certificate-chain? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a certificate chain, @racket[#f]
otherwise. Certificate chains implement the @racket[certificate-chain<%>]
interface.

This library maintains the invariant that a certificate chain object contains a
non-empty list of certificates that satisfy the @emph{chain-validity}
properties: each certificate is the issuer of the next, each certificate in the
chain has a valid signature, and the validity period of the chain is
non-empty. However, @emph{chain-validity} is only a basic well-formedness
property; it does not mean that the end certificate is @emph{valid for a given
purpose}. In particular:
@itemlist[

@item{A chain does not necessarily start with a trusted root CA.}
@item{A chain is not necessarily valid at the current time.}
@item{A chain's end certificate is not necessarily valid for a given purpose
(for example, for identifying particular a TLS server and creating a TLS
connection).}

]
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
the period from @racket[from-time] to @racket[to-time]; otherwise, return
@racket[#f].
}

@defmethod[(suitable-for-tls-server [host string?]) boolean?]{

Returns @racket[#t] if the chain ends with a certificate that is suitable for
identifying a TLS server and matches the given @racket[host] DNS name;
otherwise, returns @racket[#f].

Equivalent to
@racketblock[
(send (send @#,(this-obj) get-end-certificate)
      suitable-for-tls-server host)
]
}
}

@; ----------------------------------------

@defproc[(certificate-store? [v any/c]) boolean?]{

Returns @racket[#f] if @racket[v] is a certificate store, @racket[#f]
otherwise. Certificate stores implement the @racket[certificate-store<%>]
interface.
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

@bibliography[
#:tag "x509-bibliography"

@bib-entry[#:key "X509"
           #:title "RFC 5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"
           #:url "https://tools.ietf.org/html/rfc5280"]
]
