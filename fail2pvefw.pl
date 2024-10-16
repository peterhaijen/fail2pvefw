#!/usr/bin/perl

use strict;
use warnings;

use Data::Validate::IP qw(is_ip is_ipv4);
use DB_File;
use File::Basename;
use Getopt::Long qw(HelpMessage);
use POSIX qw(strftime);

# Change as appropriate
my $apitoken = 'PVEAPIToken=fail2ban@pve!fail2ban=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
my $host = qw(192.168.0.1);

GetOptions(
  'comment=s'   => \(my $comment = 'Added by fail2pvefw'),
  'foreground'  => \ my $foreground,
  'help'        => sub { HelpMessage(0) },
  'ipset=s'     => \(my $ipset = 'fail2ban'),
  'timestamp=f' => \(my $timestamp = time()),
) or HelpMessage(1);

$comment = strftime "[%Y/%m/%d %H:%M:%S] $comment", localtime($timestamp);

=pod

=head1 NAME

fail2pvefw.pl - insert banned IP's in an IPSet on a Proxmox host

=head1 SYNOPSIS

fail2pvefw.pl [-fh] [-i <IPSet>] [-c comment] <ban|unban> <cidr>

  -c,--comment    Comment added (defaults to 'Added on YYYY/MM/DD HH:MM:SS')
  -f,--foreground Do not background the job. Necessary once if the SSL
                  certificate requires approving.
  -h,--help       Print this help
  -i,--ipset      IPSet to use (defaults to 'fail2ban')

=cut

print STDERR "Wrong number of arguments!\n" and HelpMessage(1) unless $#ARGV+1 == 2;

my $command = shift;
print STDERR "Invalid command: $command\n" and HelpMessage(1) unless $command =~ /^(un)?ban$/;

my $ip = shift;
unless ( is_ip($ip) ) {
    my ($address, $prefix_length) = $ip =~ /^([\d\w:\.]+)\/?(\d+)?$/;
    print STDERR "Not a valid IP: $address\n" and HelpMessage(1) unless is_ip($address);
    print STDERR "Invalid prefix length: $prefix_length\n" and HelpMessage(1) unless $prefix_length <= (is_ipv4($address) ? 32 : 128);
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

    # Do not enforce strict SSL checks
    ssl_opts => { verify_hostname => 0 },
    # allow manual fingerprint verification
    manual_verification => 1,
    # and store the result in a persistent hash for future use
    cached_fingerprints => \%cache,
    );

if ( "ban" eq $command ) {
    $conn->post("/cluster/firewall/ipset/$ipset", { cidr => $ip, comment => $comment });
} else {
    $conn->delete("/cluster/firewall/ipset/$ipset/$ip", {});
}
 
exit 0;
