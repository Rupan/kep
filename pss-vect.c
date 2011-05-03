#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <gmp.h>
#include "pkcs1.h"
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

int main(int argc, char **argv) {
  int ret;
  rsa_t rsa;
  datum_t em, m;
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
