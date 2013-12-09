package AnyEvent::DNS::EtcHosts;

=head1 NAME

AnyEvent::DNS::EtcHosts - Use /etc/hosts before DNS

=head1 SYNOPSIS

  use AnyEvent::DNS::EtcHosts;
  use AnyEvent::DNS;

  my $guard = AnyEvent::DNS::EtcHosts->register;
  my $cv = AE::cv;

  AnyEvent::DNS::any 'example.com', sub {
      say foreach map { $_->[4] } grep { $_->[1] =~ /^(a|aaaa)$/ } @_;
      $cv->send;
  };

=head1 DESCRIPTION

AnyEvent::DNS::EtcHosts changes AnyEvent::DNS behavior. The F</etc/hosts> file
is searched before DNS, so it is possible to override DNS entries.

The DNS lookup are emulated so this resolver returns the standard DNS reply
based on F</etc/hosts> file rather than real DNS.

=for readme stop

=cut


use 5.008_001;
use strict;
use warnings;

our $VERSION = '0.01';

use base 'AnyEvent::DNS';

use AnyEvent ();
use AnyEvent::Socket ();
use Data::Dumper;


=head1 METHODS

=head2 register

  $guard = AnyEvent::DNS::EtcHosts->register;

=cut

sub register {
    my ($class, %args) = @_;

    my $old = $AnyEvent::DNS::RESOLVER;
    $AnyEvent::DNS::RESOLVER = AnyEvent::DNS::EtcHosts->new(
        %args
    );
    AnyEvent::Util::guard {
        $AnyEvent::DNS::RESOLVER = $old;
    };
}


=head2 request

  $resolver->request($req, $cb->($res))

=cut

# Helper functions taken from AnyEvent::Socket

our %HOSTS;          # $HOSTS{$nodename}[$ipv6] = [@aliases...]
our @HOSTS_CHECKING; # callbacks to call when hosts have been loaded
our $HOSTS_MTIME;

sub _parse_hosts($) {
   %HOSTS = ();

   for (split /\n/, $_[0]) {
      s/#.*$//;
      s/^[ \t]+//;
      y/A-Z/a-z/;

      my ($addr, @aliases) = split /[ \t]+/;
      next unless @aliases;

      if (my $ip = AnyEvent::Socket::parse_ipv4 $addr) {
         ($ip) = $ip =~ /^(.*)$/s if AnyEvent::TAINT;
         push @{ $HOSTS{$_}[0] }, $ip
            for @aliases;
      } elsif ($ip = AnyEvent::Socket::parse_ipv6 $addr) {
         ($ip) = $ip =~ /^(.*)$/s if AnyEvent::TAINT;
         push @{ $HOSTS{$_}[1] }, $ip
            for @aliases;
      }
   }
}

# helper function - unless dns delivered results, check and parse hosts, then call continuation code
sub _load_hosts_unless(&$@) {
   my ($cont, $cv, @dns) = @_;

   if (@dns) {
      $cv->end;
   } else {
      my $etc_hosts = length $ENV{PERL_ANYEVENT_HOSTS} ? $ENV{PERL_ANYEVENT_HOSTS}
                      : AnyEvent::WIN32                ? "$ENV{SystemRoot}/system32/drivers/etc/hosts"
                      :                                  "/etc/hosts";

      push @HOSTS_CHECKING, sub {
         $cont->();
         $cv->end;
      };

      unless ($#HOSTS_CHECKING) {
         # we are not the first, so we actually have to do the work
         require AnyEvent::IO;

         AnyEvent::IO::aio_stat ($etc_hosts, sub {
            if ((stat _)[9] ne ($HOSTS_MTIME||0)) {
               AE::log 8 => "(re)loading $etc_hosts.";
               $HOSTS_MTIME = (stat _)[9];
               # we might load a newer version of hosts,but that's a harmless race,
               # as the next call will just load it again.
               AnyEvent::IO::aio_load ($etc_hosts, sub {
                  _parse_hosts $_[0];
                  (shift @HOSTS_CHECKING)->() while @HOSTS_CHECKING;
               });
            } else {
               (shift @HOSTS_CHECKING)->() while @HOSTS_CHECKING;
            }
         });
      }
   }
}

sub request {
    my ($self, $req, $cb) = @_;
    warn "req = ". Dumper $req if $ENV{DEBUG};

    my $domain = $req->{qd}[0][0];
    $domain =~ s/^_[a-z0-9-]*\._[a-z0-9-]*\.// if ($req->{qd}[0][1] eq 'srv');

    my $type = $req->{qd}[0][1];

    my (@ipv4, @ipv6);

    my $cv = AE::cv;
    _load_hosts_unless {
        eval { push @ipv4, @{ ($HOSTS{$domain})->[0] } }
            if $type =~ /^([*]|srv|a)$/;
        eval { push @ipv6, @{ ($HOSTS{$domain})->[1] } }
            if $type =~ /^([*]|srv|aaaa)$/;
    } $cv;

    if (@ipv4 or @ipv6) {
        my $res = {
            id => int rand(0xffff),
            op => 'query',
            rc => 'noerror',
            qr => 1,
            aa => '',
            tc => '',
            rd => $req->{rd},
            ra => 1,
            ad => '',
            cd => '',
            qd => $req->{qd},
            an => [
                (map { [ $domain, 'a', 'in', 0, AnyEvent::Socket::format_ipv4 $_ ] } @ipv4),
                (map { [ $domain, 'aaaa', 'in', 0, AnyEvent::Socket::format_ipv6 $_ ] } @ipv6),
            ],
            ns => [],
            ar => [],
        };

        warn "res = ". Dumper $res if $ENV{DEBUG};

        return $cb->($res);
    }

    return $self->SUPER::request($req, sub {
        my ($res) = @_;
        warn "SUPER::request res = ". Dumper $res if $ENV{DEBUG};
        $cb->($res);
    });
}


1;


=for readme continue

=head1 SEE ALSO

L<AnyEvent::DNS>,
L<AnyEvent::Socket>.

=head1 BUGS

If you find the bug or want to implement new features, please report it at
L<https://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts/issues>

The code repository is available at
L<http://github.com/dex4er/perl-AnyEvent-DNS-EtcHosts>

=head1 AUTHOR

Piotr Roszatycki <dexter@cpan.org>

=head1 LICENSE

Copyright (c) 2013 Piotr Roszatycki <dexter@cpan.org>.

This is free software; you can redistribute it and/or modify it under
the same terms as perl itself.

See L<http://dev.perl.org/licenses/artistic.html>
