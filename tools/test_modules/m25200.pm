#!/usr/bin/env perl

##
## Author......: See docs/credits.txt
## License.....: MIT
##

use strict;
use warnings;

use Digest::SHA qw (sha1 sha1_hex);
use Digest::HMAC qw (hmac hmac_hex);

sub module_constraints { [[1, 256], [2, 1500], [-1, -1], [-1, -1], [-1, -1]] }

sub module_generate_hash
{
  my $word = shift;
  my $salt = shift;
  my $pkt_num = shift // int(rand(99999999));
  my $engineID = shift // random_hex_string(12);

#  $word = "pippoxxx";
  $engineID = "80001f888059dc486145a26322";
  $salt = "30820144020103301102043cdca370020300ffe304010302010304383036040d80001f888059dc486145a2632202010802020aba0406706970706f33040c0000000000000000000000000408f9a7cd5639adc7de0481f12d4e0febddef162199aa61bb97f44b84d975d9cef001d31eed660a193c22362c2ba6d203932822baa6c5d0032cc5cd7a8b7ac7b2fc005820ea72d72ffe59d3696be2bc8d5bdffb2de6fc775ed26cbf2d49a513704867665126775b8ffcaf3c07c19f9ecefb20293af7a6beecb6a5f2e3ba812ed9d71d21679007546f3acc6b72aff2baff2688451e74434dc9e6dab2f1b5e149691ced9fb4283fc8f85e3e7ebbe833353076fbdea7a11bc13a8c5ea62385b519e8bd2ab15f646572f487c8eb471eb0b069c5cc500eb8abc0227746d4ee8a5d9f0d6bfd9ece27f3f99ad5937c3e9be08e3074963796d3a13907fa1f17d213";

  my $word_len = length ($word);

  my $state = Digest::SHA->new(1);

=pod
  my $string1 = $word x (1048576 / $word_len);

print "string len: ", length($string1);

  my $sha1_digest1 = sha1_hex ($string1);

#  print "sha1_string1: ", $sha1_string1;
=cut

  my @pwd = ($word);
  my @pwd_buf = (0); # x 72;
  my $count = 0;
  my $idx_pwd = 0;
  my $idx = 0;

  while ($count < 1048576)
  {
    $idx_pwd = 0;

    for (my $i = 0; $i < 64; $i++)
    {
      $pwd_buf[$idx_pwd++] = $pwd[$idx++];
      if ($idx >= $word_len)
      {
        $idx = 0;
      }
    }

    my $tmp = join '', grep defined, @pwd_buf;

    $state->add($tmp);

    $count += 64;
  }

  my $sha1_digest1 = $state->hexdigest;

  my $buf = join '', $sha1_digest1, $engineID, $sha1_digest1;

  my $sha1_digest2 = sha1(pack("H*", $buf));

  my $digest = hmac_hex (pack("H*", $salt), $sha1_digest2, \&sha1);

  $digest = substr ($digest, 0, 24);

  my $hash = sprintf ("\$SNMPv3\$2\$%s\$%s\$%s\$%s", $pkt_num, $salt, $engineID, $digest);

  return $hash;
}

sub module_verify_hash
{
  my $line = shift;

  my $idx = index ($line, ':');

  return unless $idx >= 0;

  my $hash = substr ($line, 0, $idx);
  my $word = substr ($line, $idx + 1);

  return unless substr ($hash, 0, 10) eq '$SNMPv3$2$';

  my (undef, $signature, $version, $pkt_num, $salt, $engineID, $digest) = split '\$', $hash;

  return unless defined $signature;
  return unless defined $version;
  return unless defined $pkt_num;
  return unless defined $salt;
  return unless defined $engineID;
  return unless defined $digest;

  my $word_packed = pack_if_HEX_notation ($word);

  my $new_hash = module_generate_hash ($word_packed, $salt, $pkt_num, $engineID); #, $digest);

  return ($new_hash, $word);
}

1;
