#!/usr/bin/perl
# basic code by Eric Vyncke
use Socket qw(AF_INET6 inet_pton);

$fd = STDIN;
$option = shift;
$count = 0;
$ln = 0;

if ($option eq "" || $option eq "-h") {
  print "Syntax: grep6.pl [-n] ipv6-address [logfile]\n";
  print "Option: -n print with line count\n";
  exit(0);
}

if ($option eq "-n") {
  $count = 1;
  $option = shift;
}

my (@words, $word, $binary_address, $address) ;
$address = inet_pton AF_INET6, $option ;
if (! $address) { die "Wrong IPv6 address passed as argument" ; }

$option2 = shift;
if ($option2 ne "") {
  open $fd, "< $option2"		or die "$option2";
}

## go through the file one line at a time
while (my $line = <$fd>) {
  $ln++;
  @words = split /[ ,"'.\\\t\n\r\(\)\[\]]/, $line ;
  foreach $word (@words) {
    $binary_address = inet_pton AF_INET6, $word ;
    if ($binary_address eq $address) {
      print "$ln: "	if ($count == 1);
      print $line ;
      next ;
    }
  }
}
