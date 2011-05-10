/*
  PKCS#1 v2.1: check EMSA-PSS test vectors against PKCS1 code
  Copyright (C) 2011 Michael Mohr <akihana@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
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
  uint8_t EM[256];

  mlockall(MCL_CURRENT|MCL_FUTURE);

  rsa_init(&rsa);

  em.data = (uint8_t *)EM;
  em.size = (uint32_t)sizeof(EM);

/*
generate these with gentests.pl
NOTE: in some cases, the RSA signing operation will produce a signature which
is 1 or more bytes less in length than N.  In these cases, it must be padded
on the left with zeros.
*/
#include "tests.c"

  rsa_free(&rsa);

  munlockall();

  return 0;
}
