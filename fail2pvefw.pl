#!/usr/bin/perl

use strict;
use warnings;

use Data::Dump;
use Data::Validate::IP qw(is_ip is_ipv4);
use DB_File;
use Getopt::Long qw(HelpMessage);
use IO::Socket::SSL qw(SSL_VERIFY_NONE SSL_VERIFY_PEER);
use IO::Socket;
use POSIX qw(strftime);

# Change as appropriate
my $apitoken = 'PVEAPIToken=fail2ban@pve!fail2ban=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
my $host = qw(192.168.0.1);

GetOptions(
  'comment=s'   => \(my $comment = 'Added by fail2pvefw'),
  'foreground'  => \ my $foreground,
  'help'        => sub { HelpMessage(0) },
  'ipset=s'     => \(my $ipset = 'fail2ban'),
  'manual'      => \(my $manual_verification = 0),
  'timestamp=f' => \(my $timestamp = time()),
) or HelpMessage(1);

$comment = strftime "[%Y/%m/%d %H:%M:%S] $comment", localtime($timestamp);
$foreground = 1 if $manual_verification;

=pod

=head1 NAME

fail2pvefw.pl - insert banned IP's in an IPSet on a Proxmox host

=head1 SYNOPSIS

fail2pvefw.pl [-fhm] [-t timestamp] [-i <IPSet>] [-c comment] <ban|unban|dns> <host>

  -c,--comment    Comment added (defaults to 'Added on YYYY/MM/DD HH:MM:SS')
  -f,--foreground Do not background the job
  -h,--help       Print this help
  -i,--ipset      IPSet to use - defaults to 'fail2ban'
  -m,--manual     Allow manual SSL certificate verification - implies -f!
  -t,--timestamp  Timestamp of ba, in secs since epoch

=cut

print STDERR "Wrong number of arguments!\n" and HelpMessage(1) unless $#ARGV+1 == 2;

my $command = shift;
my $host_or_ip = shift;

if ( 'dns' eq $command ) {

  # Recieved a hostname, which we will resolve, then add/update in the IPSet

} elsif ( $command =~ /^(un)?ban$/ ) {

  # Received a cidr, which must be added (ban) or removed (unban) from the IPSet

  unless ( is_ip($host_or_ip) ) {
    my ($address, $prefix_length) = $host_or_ip =~ /^([\d\w:\.]+)\/?(\d+)?$/;
    print STDERR "Not a valid IP: $address\n" and HelpMessage(1) unless is_ip($address);
    print STDERR "Invalid prefix length: $prefix_length\n" and HelpMessage(1) unless $prefix_length <= (is_ipv4($address) ? 32 : 128);
  }

} else {

  print STDERR "Invalid command: $command\n" and HelpMessage(1);
}

# Run the remainder of the script in background, unless running in foreground mode
unless ( $foreground ) {
  exit(0) if ( fork or fork );

  close STDIN;
  close STDOUT;
  close STDERR;
}

# What follows is executed in background mode (the default)
require PVE::APIClient::LWP;

tie my %cache, 'DB_File', '/var/run/cached_fingerprints.db', O_CREAT|O_RDWR, 0666;

my $conn = PVE::APIClient::LWP->new(
    # Requires Sys.Audit and Sys.Modify permissions
    apitoken => $apitoken,
    host => $host,

    # Do not enforce strict SSL checks. Note that for some reason SSL_VERIFY_NONE does not work...
    ssl_opts => { SSL_verify_mode => SSL_VERIFY_NONE, verify_hostname => 0 },
    # allow manual fingerprint verification
    manual_verification => $manual_verification,
    # and store the result in a persistent hash for future use
    cached_fingerprints => \%cache,
    );

if ( "ban" eq $command ) {
    $conn->post("/cluster/firewall/ipset/$ipset", { cidr => $host_or_ip, comment => $comment });
} elsif ( "unban" eq $command ) {
    $conn->delete("/cluster/firewall/ipset/$ipset/$host_or_ip", {});
} elsif ( "dns" eq $command ) {

  my @addresses = gethostbyname($host_or_ip) or die "Can't resolve $host_or_ip: $!\n";
  my %addresses; map { $addresses{inet_ntoa($_)} = 1 } @addresses[4 .. $#addresses];

  my $result = $conn->get("/cluster/firewall/ipset/$ipset", {});
  #dd($result);

  # First step: cleanup what's in the IPSet
  foreach my $ip ( @{$result} ) {

    if ( exists $addresses{$ip->{'cidr'}} ) {

      # Found an IP we're about to add/update.

      if ( $ip->{'comment'} ne $host_or_ip ) {

        # The IP has the wrong hostname, delete this
        $conn->delete("/cluster/firewall/ipset/$ipset/$ip->{'cidr'}", {});
      } else {

        # Found a matching IP with the correct hostname, nothing to do
        delete $addresses{$ip->{'cidr'}}
      }
    } elsif ( $ip->{'comment'} eq $host_or_ip ) {

      # Found an IP for this hostname that we don't know about
      # This is possibly an obsolete IP
      $conn->delete("/cluster/firewall/ipset/$ipset/$ip->{'cidr'}", {});
    }
  }

  # Second step: add all IPs we still have in our list
  foreach my $ip ( keys %addresses ) {
    $conn->post("/cluster/firewall/ipset/$ipset", { cidr => $ip, comment => $host_or_ip });
  }

} else {
  # This should never happen
}

exit 0;
