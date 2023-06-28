# AnyEvent::DNS::EtcHosts

[![CI](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/actions/workflows/ci.yaml/badge.svg)](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/actions/workflows/ci.yaml)
[![Trunk Check](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/actions/workflows/trunk.yaml/badge.svg)](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/actions/workflows/trunk.yaml)
[![CPAN](https://img.shields.io/cpan/v/AnyEvent-DNS-EtcHosts)](https://metacpan.org/dist/AnyEvent-DNS-EtcHosts)

## NAME

AnyEvent::DNS::EtcHosts - Use /etc/hosts before DNS

## SYNOPSIS

```perl

    use AnyEvent::DNS::EtcHosts;

    use AnyEvent::DNS;
    my $cv = AE::cv;
    AnyEvent::DNS::any 'example.com', sub {
        say foreach map { $_->[4] } grep { $_->[1] =~ /^(a|aaaa)$/ } @_;
        $cv->send;
    };

    use AnyEvent::Socket;
    my $cv = AE::cv;
    AnyEvent::Socket::resolve_sockaddr $domain, $service, $proto, $family, undef, sub {
        say foreach map { format_address((AnyEvent::Socket::unpack_sockaddr($_->[3]))[1]) } @_;
        $cv->send;
    };

```

## DESCRIPTION

AnyEvent::DNS::EtcHosts changes AnyEvent::DNS behavior. The `/etc/hosts` file
is searched before DNS, so it is possible to override DNS entries.

The DNS lookups are emulated. This resolver returns the standard DNS reply
based on `/etc/hosts` file rather than real DNS.

You can choose a different file by changing `PERL_ANYEVENT_HOSTS` environment
variable.

This module also disables the original [AnyEvent::Socket](https://metacpan.org/pod/AnyEvent%3A%3ASocket)'s helper function
which reads `/etc/hosts` file after the DNS entry was not found. It prevents
reading this file twice.

The [AnyEvent::Socket](https://metacpan.org/pod/AnyEvent%3A%3ASocket) resolver searches IPv4 and IPv6 addresses separately.
If you don't want to check the addresses in DNS, both IPv4 and IPv6 addresses
should be placed in `/etc/hosts` or the protocol family should be set
explicitly for `resolve_sockaddr` function.

## IMPORTS

## use AnyEvent::DNS::EtcHosts %args

```perl

use AnyEvent::DNS::EtcHosts server => '8.8.8.8';

$ perl -MAnyEvent::DNS::EtcHosts script.pl

```

Enables this module globally. Additional arguments will be passed to
[AnyEvent::DNS](https://metacpan.org/pod/AnyEvent%3A%3ADNS) constructor.

## no AnyEvent::DNS::EtcHosts

Disables this module globally.

## METHODS

## register

```perl

    require AnyEvent::DNS::EtcHosts;

    $guard = AnyEvent::DNS::EtcHosts->register(%args);

    undef $guard;

```

Enables this module in lexical scope. The module will be disabled out of
scope. Additional arguments will be passed to [AnyEvent::DNS](https://metacpan.org/pod/AnyEvent%3A%3ADNS) constructor.

If you want to use AnyEvent::DNS::EtcHosts in lexical scope only, you should
use `require` rather than `use` keyword, because `import` method enables
AnyEvent::DNS::EtcHosts globally.

## request

```perl

    $resolver->request($req, $cb->($res))

```

This is a wrapper for [AnyEvent::DNS](https://metacpan.org/pod/AnyEvent%3A%3ADNS)->request method.

## SEE ALSO

[AnyEvent::DNS](https://metacpan.org/pod/AnyEvent%3A%3ADNS),
[AnyEvent::Socket](https://metacpan.org/pod/AnyEvent%3A%3ASocket).

## BUGS

This module might be incompatible with further versions of [AnyEvent](https://metacpan.org/pod/AnyEvent) module.

If you find the bug or want to implement new features, please report it at
[https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/issues](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/issues)

The code repository is available at
[http://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts](http://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts)

## AUTHORS

Piotr Roszatycki <dexter@cpan.org>

Helper functions taken from AnyEvent::Socket 7.05 by
Marc Lehmann <schmorp@schmorp.de>

## LICENSE

Copyright (c) 2013-2014, 2023 Piotr Roszatycki <dexter@cpan.org>.

This is free software; you can redistribute it and/or modify it under
the same terms as perl itself.

See [http://dev.perl.org/licenses/artistic.html](http://dev.perl.org/licenses/artistic.html)
