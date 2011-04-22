#!/usr/bin/perl

use warnings;
use strict;
use POSIX qw/ceil/;

my $bits = 1023;

for(my $i = 1; $i <= 10; $i++) {
  if( $i < 9 ) {
    $bits++;
  } elsif( $i == 9 ) {
    $bits = 1536;
  } else {
    $bits = 2048;
  }
  my $bytes = ceil($bits/8);

  print "  mpz_import(rsa.n, sizeof(k${i}n), 1, 1, 1, 0, k${i}n);\n";
  print "  mpz_import(rsa.e, sizeof(k${i}e), 1, 1, 1, 0, k${i}e);\n";
  print "  mpz_import(rsa.d, sizeof(k${i}d), 1, 1, 1, 0, k${i}d);\n";
  print "  mpz_import(rsa.p, sizeof(k${i}p), 1, 1, 1, 0, k${i}p);\n";
  print "  mpz_import(rsa.q, sizeof(k${i}q), 1, 1, 1, 0, k${i}q);\n";
  print "  mpz_import(rsa.dmp1, sizeof(k${i}dP), 1, 1, 1, 0, k${i}dP);\n";
  print "  mpz_import(rsa.dmq1, sizeof(k${i}dQ), 1, 1, 1, 0, k${i}dQ);\n";
  print "  mpz_import(rsa.iqmp, sizeof(k${i}qInv), 1, 1, 1, 0, k${i}qInv);\n";

  print "  printf(\"Using key ${i}...\\n\");\n";
  for(my $j = 1; $j <= 6; $j++) {
    my $base = "k${i}m${j}";
    print "  printf(\"\tmessage ${j} [bits:bytes => $bits:$bytes] \");\n";
    print "  salt = ${base}_salt;\n";
    print "  m.data = (uint8_t *)${base}_plain;\n";
    print "  m.size = (uint32_t)sizeof(${base}_plain);\n";
    print "  emsa_pss_encode(EM, $bits, &m);\n";
    print "  ret = emsa_pss_verify(EM, $bits, &m);\n";
    print "  emsa_pss_encode(EM, $bits, &m);\n";
    print "  rsasp1(SM, EM, &rsa);\n";
    print "  ret = memcmp(${base}_sig, SM, $bytes );\n";
    print "  if( ret != 0 ) {\n";
    print "    printf(\"FAILURE.  <---\\n\");\n";
    print "    printf(\"\\n\\n\");\n";
    print "    printf(\"Precalculated signature:\\n\");\n";
    print "    print_bytes(${base}_sig, sizeof(${base}_sig));\n";
    print "    printf(\"\\n\\n\");\n";
    print "    printf(\"Calculated signature:\\n\");\n";
    print "    print_bytes(SM, $bytes);\n";
    print "    printf(\"\\n\\n\");\n";
    print "  } else {\n";
    print "    printf(\"success.\\n\");\n";
    print "  }\n";
  }

  print "\n\n";
}
