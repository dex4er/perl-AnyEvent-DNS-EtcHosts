#!/usr/bin/perl

use v5.14;

use lib 'lib', '../lib';

my $domain = $ARGV[0] || 'example.com';

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
