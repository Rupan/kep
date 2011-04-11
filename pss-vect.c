#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <gmp.h>
#include "emsa-pss.h"
#include "pss-vect.h"

const uint8_t *salt;

static void print_bytes(const uint8_t *data, uint32_t len) {
  uint32_t i;

  for(i = 0; i < len; i++) {
    if( (i + 1) % 16 == 0 ) {
      printf("0x%02X,\n", data[i]);
    } else {
      printf("0x%02X, ", data[i]);
    }
  }
}

int32_t fill_random(uint8_t *dst, uint32_t dlen) {
  dlen = 0;
  memcpy(dst, salt, 20);
  return 0;
}

/*
RSA signature primitive 1, using the original method

The storage sizes of the mesasge and the signature are assumed to be
equal to the size of n in octets.
*/
void rsasp1_v1(uint8_t *signature, uint8_t *message, rsa_t *rsa) {
  size_t ctbits, ctbytes;
  size_t nbits, nbytes;
  uint32_t diff, i;
  mpz_t pt, ct;

  mpz_init(pt);
  mpz_init(ct);

  nbits = mpz_sizeinbase(rsa->n, 2);
  nbytes = nbits >> 3;
  if( nbits % 8 ) nbytes++;
  mpz_import(pt, nbytes, 1, 1, 1, 0, message);

  /**********************STD*************************/

  mpz_powm(ct, pt, rsa->d, rsa->n);

  /**************************************************/

  ctbits = mpz_sizeinbase(ct, 2);
  ctbytes = ctbits >> 3;
  if( ctbits % 8 ) ctbytes++;
  diff = nbytes-ctbytes;
  for(i = 0; i < diff; i++) signature[i] = 0;
  mpz_export(signature+diff, NULL, 1, 1, 1, 0, ct);

  mpz_clear(pt);
  mpz_clear(ct);
}

int main(int argc, char **argv) {
  int ret;
  rsa_t rsa;
  uint8_t EM[256], SM[256];

  rsa_init(&rsa);

/*
generate these with gentests.pl
NOTE: in some cases, the RSA signing operation will produce a signature which
is 1 or more bytes less in length than N.  In these cases, it must be padded
on the left with zeros.
*/
#include "tests.c"

  rsa_free(&rsa);

  return 0;
}
