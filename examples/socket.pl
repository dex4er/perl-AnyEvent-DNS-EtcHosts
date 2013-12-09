#!/usr/bin/perl

use v5.14;

use lib 'lib', '../lib';

my $domain = $ARGV[0] || 'example.com';

use File::Temp 'tempfile';

if (not $ENV{PERL_ANYEVENT_HOSTS}) {
    my ($fh, $filename) = tempfile(TMPDIR => 1);
    say $fh '1.2.3.4 example.com';
    say $fh '5.6.7.8 example.com';
    say $fh 'fe00::1234 example.com';
    close $fh;
    $ENV{PERL_ANYEVENT_HOSTS} = $filename;
}

use AnyEvent::DNS::EtcHosts;

my $guard = AnyEvent::DNS::EtcHosts->register;

use AnyEvent::Socket;
use Socket;

my $cv = AE::cv;

AnyEvent::Socket::resolve_sockaddr $domain, 'http', 'tcp', undef, undef, sub {
    say foreach map { format_address((AnyEvent::Socket::unpack_sockaddr($_->[3]))[1]) } @_;
    $cv->send;
};

$cv->recv;

undef $guard;
