# NAME

AnyEvent::DNS::EtcHosts - Use /etc/hosts before DNS

# SYNOPSIS

    use AnyEvent::DNS::EtcHosts;
    use AnyEvent::DNS;

    my $guard = AnyEvent::DNS::EtcHosts->register;
    my $cv = AE::cv;

    AnyEvent::DNS::any 'example.com', sub {
        say foreach map { $_->[4] } grep { $_->[1] =~ /^(a|aaaa)$/ } @_;
        $cv->send;
    };

undef $guard;

# DESCRIPTION

AnyEvent::DNS::EtcHosts changes AnyEvent::DNS behavior. The `/etc/hosts` file
is searched before DNS, so it is possible to override DNS entries.

The DNS lookup are emulated so this resolver returns the standard DNS reply
based on `/etc/hosts` file rather than real DNS.

# METHODS

## register

    $guard = AnyEvent::DNS::EtcHosts->register;

## request

    $resolver->request($req, $cb->($res))

# SEE ALSO

[AnyEvent::DNS](https://metacpan.org/pod/AnyEvent::DNS),
[AnyEvent::Socket](https://metacpan.org/pod/AnyEvent::Socket).

# BUGS

If you find the bug or want to implement new features, please report it at
[https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/issues](https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/issues)

The code repository is available at
[http://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts](http://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts)

# AUTHOR

Piotr Roszatycki <dexter@cpan.org>

# LICENSE

Copyright (c) 2013 Piotr Roszatycki <dexter@cpan.org>.

This is free software; you can redistribute it and/or modify it under
the same terms as perl itself.

See [http://dev.perl.org/licenses/artistic.html](http://dev.perl.org/licenses/artistic.html)
