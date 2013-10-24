#lang scribble/doc
@(require scribble/manual
          scribble/basic
          (for-label racket/base
                     racket/contract
                     crypto))

@title[#:tag "dh"]{Diffie-Hellman Key Exchange}

Diffie-Hellman key parameters are encapsulated in instances of @scheme[<dh>].
Keys can be generated from a parameter instance using @scheme[generate-key].

@deftogether[(
@defthing[dh:192 <dh>]
@defthing[dh:512 <dh>]
@defthing[dh:1024 <dh>]
@defthing[dh:2048 <dh>]
@defthing[dh:4096 <dh>]
)]{
Pre-computed Diffie-Hellman parameters from the OpenSSL project.
}

@defproc[(compute-key (priv dhkey?) (key bytes?)) bytes?]{
Computes a shared key using the private key @scheme[priv] and the peer 
public key @scheme[key].
}

@defproc[(dhkey? (o _)) boolean?]{
True if @scheme[o] is a Diffie-Hellman key.
}

@defproc[(!dh? (o _)) boolean?]{
True if @scheme[o] is a @scheme[<dh>] parameter object.
}

@defproc[(dh-bits (o <dh>)) exact-nonnegative-integer?]{
The size in bits of the keys generated from @scheme[o].
}
