#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     racket/random
                     crypto
                     crypto/all
                     crypto/libcrypto
                     crypto/nettle
                     crypto/gcrypt))

@title[#:tag "factory"]{Cryptography Factories}

This library relies on foreign libraries for the implementations of
cryptographic primitives. Each foreign library is called a
@emph{cryptography provider} and it has an associated @emph{factory}
that map cryptographic @emph{algorithm specifiers} to
@emph{implementations}.

Cryptography providers may be used to obtain algorithm implementations
either explicitly or implicitly. An implementation of a cryptographic
algorithm may be obtained @emph{explicitly} by calling the appropriate
function (eg, @racket[get-digest], @racket[get-cipher], etc) on a
factory or list of factories. Alternatively, most functions provided
by this library for performing cryptographic operations accept either
a implementation object or an algorithm specifier. If an algorithm
specifier is given, an implementation is @emph{implicitly} sought from
the factories in @racket[(crypto-factories)]; if no implementation is
available, an exception is raised.

@defproc[(crypto-factory? [v any/c]) boolean?]{

Returns @racket[#t] if @racket[v] is a crypto factory, @racket[#f]
otherwise.
}

@defparam[crypto-factories factories (listof crypto-factory?)]{

The list of crypto factories used when implicitly finding an
implementation of a cryptographic algorithm from an algorithm
specifier.

The initial value is @racket['()].
}

@defproc[(get-factory [i (or/c digest-impl? digest-ctx?
                               cipher-impl? cipher-ctx?
                               pk-impl? pk-parameters? pk-key?)])
         crypto-factory?]{

Gets the factory associated with a particular cryptographic algorithm
implementation or context.
}

@defproc[(factory-print-info [factory crypto-factory?]) void?]{

Prints information about @racket[factory] to the current output
port. In particular, the following information is customarily
included, if relevant:
@itemlist[
@item{the version of the underlying foreign library (if known)}
@item{the available digests}
@item{the available ciphers}
@item{the available PK systems}
@item{the available EC named curves}
@item{the available key-derivation functions}
]
Different crypto providers support different levels of introspection,
so the information is generally provided on a best-effort basis.
}

@;{----------------------------------------}

@section[#:tag "all"]{All Factories}

@defmodule[crypto/all]

@defthing[all-factories (listof crypto-factory?)]{

A list containing all of the factories available in the library.

Warning: the order of the factories may change in future versions of
this library. This module is intended as a convenience for interactive
use, not for developing libraries or applications.
}

@defproc[(use-all-factories!) void?]{

Equivalent to @racket[(crypto-factories all-factories)].
}

@;{----------------------------------------}

@section[#:tag "libcrypto-factory"]{Libcrypto (OpenSSL)}

@defmodule[crypto/libcrypto]

@defthing[libcrypto-factory crypto-factory?]{

Factory for
@hyperlink["http://www.openssl.org/docs/crypto/crypto.html"]{libcrypto},
the cryptography library of OpenSSL. The necessary foreign library is
typically part of the operating system or distributed with Racket.
}

@section[#:tag "gcrypt-factory"]{GCrypt}

@defmodule[crypto/gcrypt]

@defthing[gcrypt-factory crypto-factory?]{

Factory for
@hyperlink["http://www.gnu.org/software/libgcrypt/"]{GCrypt} (aka
@as-index{libgcrypt}), a cryptography library from the GNU project,
originally part of GnuPG.  The @tt{libgcrypt.so.20} foreign library is
required.
}

@section[#:tag "nettle-factory"]{Nettle}

@defmodule[crypto/nettle]

@defthing[nettle-factory crypto-factory?]{

Factory for
@hyperlink["http://www.lysator.liu.se/~nisse/nettle/"]{Nettle}, a
lightweight cryptography library. The @tt{libnettle.so.6} foreign
library is required, and @tt{libhogweed.so.4} is required for
public-key crypto support.
}

@section[#:tag "sodium-factory"]{Sodium}

@defmodule[crypto/sodium]

@defthing[sodium-factory crypto-factory?]{

Factory for @hyperlink["https://download.libsodium.org/doc/"]{Sodium}
(aka @as-index{libsodium}). This factory does @bold{not} provide the
high-level Sodium APIs; it only provides access to some of the
low-level primitives. The @tt{libsodium.so.{23,18}} library is required.
}

@section[#:tag "b2-factory"]{B2 (Blake2)}

@defmodule[crypto/b2]

@defthing[b2-factory crypto-factory?]{

Factory for @hyperlink["https://github.com/BLAKE2/libb2"]{libb2}, a
small library implementing the @hyperlink["https://blake2.net/"]{Blake2}
digest and MAC algorithm. The @tt{libb2.so.1} foreign library is required.
}

@section[#:tag "argon2-factory"]{Argon2}

@defmodule[crypto/argon2]

@defthing[argon2-factory crypto-factory?]{

Factory for
@hyperlink["https://github.com/P-H-C/phc-winner-argon2"]{Argon2}, a
tiny library implementing the Argon2 password hashing (and key
derivation) function. The @tt{libargon2.so.1} foreign library is
required.
}
