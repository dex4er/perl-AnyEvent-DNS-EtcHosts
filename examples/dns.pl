#!/usr/bin/perl

# Example: dns.pl google.com

use v5.14;

use lib 'lib', '../lib';

my $domain = $ARGV[0] || 'example.com';

use AnyEvent::DNS::EtcHosts;
use AnyEvent::DNS;

my $cv = AE::cv;

AnyEvent::DNS::any $domain, sub {
    say foreach map { $_->[4] } grep { $_->[1] =~ /^(a|aaaa)$/ } @_;
    $cv->send;
};

$cv->recv;
