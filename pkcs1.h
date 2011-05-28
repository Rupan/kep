/*
  PKCS#1 v2.1: EMSA-PSS codec module header
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

#ifndef _PKCS1_H
#define _PKCS1_H

#include <inttypes.h>
#include <gmp.h>

typedef struct _rsa_t {
  mpz_t n;      /* public modulus */
  mpz_t e;      /* public exponent */
  mpz_t d;      /* private exponent */
  mpz_t p;      /* secret prime factor */
  mpz_t q;      /* secret prime factor */
  mpz_t dmp1;   /* d mod (p-1) */
  mpz_t dmq1;   /* d mod (q-1) */
  mpz_t iqmp;   /* q^-1 mod p */
} rsa_t;

typedef struct _datum_t {
  uint8_t *data;
  uint32_t size;
} datum_t;

int32_t emsa_pss_encode(datum_t *em, rsa_t *rsa, datum_t *m);
int32_t emsa_pss_verify(datum_t *em, rsa_t *rsa, datum_t *m);

void rsa_init(rsa_t *rsa);
void rsa_free(rsa_t *rsa);

#endif /* _PKCS1_H */
