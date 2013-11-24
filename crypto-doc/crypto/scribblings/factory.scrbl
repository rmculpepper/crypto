#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto
                     crypto/provider/libcrypto
                     crypto/provider/nettle
                     crypto/provider/gcrypt))

@title[#:tag "factory"]{Cryptography Providers}

This library relies on foreign libraries for the implementations of
cryptographic primitives. Each foreign library is called a
@emph{cryptography provider} and it has an associated @emph{factory}
that map cryptographic @emph{algorithm specifiers} to
@emph{implementations}. A cryptography provider may also export other
functions---for example, to initialize a random number generator.

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

@defproc[(get-factory [i (or/c digest-impl? cipher-impl? pk-impl? random-impl?)])
         crypto-factory?]{

Gets the factory associated with a particular cryptographic algorithm
implementation.
}

@;{----------------------------------------}


@section{Libcrypto (OpenSSL)}

@defmodule[crypto/provider/libcrypto]

@defthing[libcrypto-factory crypto-factory?]{

Factory for libcrypto, the cryptography library that is part of
OpenSSL. The necessary foreign library is typically part of the
operating system or distributed with Racket.
}

@section{GCrypt}

@defmodule[crypto/provider/gcrypt]

@defthing[gcrypt-factory crypto-factory?]{

Factory for the GCrypt cryptography library.
}

@section{Nettle}

@defmodule[crypto/provider/nettle]

@defthing[nettle-factory crypto-factory?]{

Factory for the Nettle cryptography library.
}


@;{
;; Doc the following in appropriate sections

@defproc[(get-random [fs (or/c crypto-factory? (listof crypto-factory?)) (crypto-factories)])
         random-impl?]{

}
}
