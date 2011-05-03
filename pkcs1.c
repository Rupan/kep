/*
  PKCS#1 v2.1: EMSA-PSS codec module
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

/* for apply_mask */
#include <endian.h>
#include <string.h>
#include <inttypes.h>
#include <gmp.h>
#include "pkcs1.h"

#ifndef BYTE_ORDER
#error The platform byte order is not defined, please fix it.
#endif

#if defined(USE_SHA1)
#include "brg-sha.h"
#define HASH_DIGEST_SIZE 20
#define HASH_CONTEXT sha1_ctx
#define HASH_STARTS(ctx) sha1_begin(ctx)
#define HASH_UPDATE(ctx, input, ilen) sha1_hash((input), (ilen), (ctx))
#define HASH_FINISH(ctx, output) sha1_end((output), (ctx))
#else
#include "brg-sha.h"
#define HASH_DIGEST_SIZE 32
#define HASH_CONTEXT sha256_ctx
#define HASH_STARTS(ctx) sha256_begin(ctx)
#define HASH_UPDATE(ctx, input, ilen) sha256_hash((input), (ilen), (ctx))
#define HASH_FINISH(ctx, output) sha256_end((output), (ctx))
#endif

void rsa_init(rsa_t *rsa) {
  mpz_init(rsa->n);
  mpz_init(rsa->e);
  mpz_init(rsa->d);
  mpz_init(rsa->p);
  mpz_init(rsa->q);
  mpz_init(rsa->dmp1);
  mpz_init(rsa->dmq1);
  mpz_init(rsa->iqmp);
}

void rsa_free(rsa_t *rsa) {
  mpz_clear(rsa->n);
  mpz_clear(rsa->e);
  mpz_clear(rsa->d);
  mpz_clear(rsa->p);
  mpz_clear(rsa->q);
  mpz_clear(rsa->dmp1);
  mpz_clear(rsa->dmq1);
  mpz_clear(rsa->iqmp);
}

/* this function must be defined: it writes dlen bytes to dst */
int32_t fill_random(uint8_t *dst, uint32_t dlen);

/* this function implements MGF1 */
static void apply_mask(uint8_t *mask, uint32_t mlen, uint8_t *seed, uint32_t slen) {
  HASH_CONTEXT ctx[1];
  uint32_t i, j, outlen, tmp, ibe;
  uint8_t md[HASH_DIGEST_SIZE];

  outlen = 0;
  for(i=0; outlen < mlen; i++) {
    ibe = (uint32_t)htobe32((unsigned int)i); /* I2OSP */
    HASH_STARTS(ctx);
    HASH_UPDATE(ctx, seed, slen);
    HASH_UPDATE(ctx, (uint8_t *)&ibe, 4);
    HASH_FINISH(ctx, md);
    if(outlen + HASH_DIGEST_SIZE <= mlen) {
      for(j = 0; j < HASH_DIGEST_SIZE; j++)
        mask[outlen++] ^= md[j];
    } else {
      tmp = mlen - outlen;
      for(j = 0; j < tmp; j++)
        mask[outlen++] ^= md[j];
    }
  }
}

static int rsavp1(datum_t *signature, datum_t *message, rsa_t *rsa) {
  int ret;
  uint32_t mBits, mBytes, diff, i;
  mpz_t s, m;

  mpz_init(s);
  mpz_init(m);
  mpz_import(s, signature->size, 1, 1, 1, 0, signature->data);
  ret = mpz_cmp(s, rsa->n);
  /* "signature representative out of range" */
  if(ret >= 0 ) {
    mpz_clear(m);
    mpz_clear(s);
    return -1;
  }
  mpz_powm(m, s, rsa->e, rsa->n);
  mBits = mpz_sizeinbase(m, 2);
  mBytes = mBits >> 3;
  if( mBits % 8 ) mBytes++;
  diff = signature->size - mBytes;
  for(i = 0; i < diff; i++) message->data[i] = 0;
  mpz_export(message->data+diff, NULL, 1, 1, 1, 0, m);
  mpz_clear(m);
  mpz_clear(s);
  return 0;
}

/*
  emsa_pss_encode: Perform EMSA-PSS signature padding (PKCS#1 v2.1)

  em     : allocated storage for the encoded message
           must be at least ceil(emBits/8.0) bytes long
  emBits : the number of bits in the RSA modulus N
  m      : the message to be signed, size is taken to be
           the length of the message to be signed
  Return values:
   0     : success
  -1     : "encoding error"
  -2     : insufficient output space in "em"
*/

int32_t emsa_pss_encode(datum_t *em, rsa_t *rsa, datum_t *m) {
  uint32_t i, emBits, emLen, psLen, offset;
  HASH_CONTEXT ctx[1];
  uint8_t mp[8+2*HASH_DIGEST_SIZE], *p, *q;

  emBits = mpz_sizeinbase(rsa->n, 2);
  emLen = (uint32_t)(emBits/8);
  if( emBits % 8 > 0 ) emLen++;
  if( emLen > em->size ) return -2;

  if( emLen < (2*HASH_DIGEST_SIZE + 2) )
    return -1;

  /* emsa-pss encoding is over sizeof(N)-1 bits */
  emBits--;
  if( emBits % 8 == 0 )
    offset = 1;
  else
    offset = 0;

  /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
  p = mp;
  for(i = 0; i < 8; i++) p[i] = 0x00;
  p += 8;
  HASH_STARTS(ctx);
  HASH_UPDATE(ctx, m->data, m->size);
  HASH_FINISH(ctx, p);
  p += HASH_DIGEST_SIZE;
  if( fill_random(p, HASH_DIGEST_SIZE) < 0 )
    return -1;

  /* DB = PS || 0x01 || salt */
  q = em->data;
  psLen = emLen - 2*HASH_DIGEST_SIZE - 2;
  for(i = 0; i < psLen; i++) q[i] = 0x00;
  q += psLen;
  *q++ = 0x01;
  for(i = 0; i < HASH_DIGEST_SIZE; i++)
    q[i] = p[i];
  q += HASH_DIGEST_SIZE;

  /* Let H = hash(M') */
  HASH_STARTS(ctx);
  HASH_UPDATE(ctx, mp, sizeof(mp));
  HASH_FINISH(ctx, q);

  apply_mask(em->data + offset, emLen - HASH_DIGEST_SIZE - 1 - offset, q, HASH_DIGEST_SIZE);
  q += HASH_DIGEST_SIZE;
  *q = 0xbc;

  /* Set the leftmost 8 * emLen - emBits bits of the leftmost octet in maskedDB to zero */
  em->data[0] &= ( 0xFF >> ( 8 * emLen - emBits ) );

  return 0;
}

/*
  em     - encoded message, an octet string
  emBits - maximal bit length of the integer OS2IP(EM)
  m      - message to be verified, an octet string
  mBytes - length of m in octets

  This function will overwrite em.

  Return values:
   0     : success
  -5     : bad first or last bytes
  -4     : bad sentinel value after PS
  -3     : PS sentinel offset does not match dbLen
  -2     : computed hash H' does not match transmitted hash H
  -1     : not enough space in em
*/

int32_t emsa_pss_verify(datum_t *em, rsa_t *rsa, datum_t *m) {
  uint8_t mask;
  int32_t ret;
  uint32_t i, emBits, emLen, dbLen, offset;
  HASH_CONTEXT ctx[1];
  uint8_t mp[8+2*HASH_DIGEST_SIZE], hp[HASH_DIGEST_SIZE],  *p, *q;

  ret = 0;
  emBits = mpz_sizeinbase(rsa->n, 2);
  emLen = (uint32_t)(emBits/8);
  if( emBits % 8 != 0 ) emLen++;
  if( em->size > emLen ) return -1;

  /* emsa-pss encoding is over sizeof(N)-1 bits */
  emBits--;
  if( emBits % 8 == 0 )
    offset = 1;
  else
    offset = 0;

  mask = ( 0xFF >> ( 8 * emLen - emBits ) );
  if( (em->data[0] & ~mask) != 0x00 || em->data[emLen-1] != 0xbc )
    ret |= 1;

  dbLen = (emLen - HASH_DIGEST_SIZE - 1);
  apply_mask(em->data + offset, dbLen - offset, em->data + dbLen, HASH_DIGEST_SIZE);
  em->data[0] &= mask;
  q = em->data;
  for(i = 0; *q == 0 && i < dbLen; i++) q++;
  if( *q++ != 0x01 ) ret |= 2;
  if( (uint32_t)((q - em->data) + HASH_DIGEST_SIZE) != dbLen ) ret |= 4;

  /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
  p = mp;
  for(i = 0; i < 8; i++) p[i] = 0x00;
  p += 8;
  HASH_STARTS(ctx);
  HASH_UPDATE(ctx, m->data, m->size);
  HASH_FINISH(ctx, p);
  p += HASH_DIGEST_SIZE;
  for(i = 0; i < HASH_DIGEST_SIZE; i++)
    p[i] = q[i];

  /* Let H' = Hash(M'), an octet string of length hLen */
  HASH_STARTS(ctx);
  HASH_UPDATE(ctx, mp, sizeof(mp));
  HASH_FINISH(ctx, hp);

  q = em->data + dbLen;
  for(i = 0; i < HASH_DIGEST_SIZE; i++) {
    if( q[i] != hp[i] )
      ret |= 8;
  }
  return ret;
}

/*
RSA signature primitive 1, using the Chinese Remainder Theorem

The storage sizes of the mesasge and the signature are assumed to be
equal to the size of n in octets.
*/
void rsasp1(uint8_t *signature, uint8_t *message, rsa_t *rsa) {
  uint32_t diff, i;
  mpz_t m, h, s, s1, s2;
  size_t ptbits, ptbytes, ctbits, ctbytes;

  mpz_init(m);
  mpz_init(h);
  mpz_init(s);
  mpz_init(s1);
  mpz_init(s2);

  ptbits = mpz_sizeinbase(rsa->n, 2);
  ptbytes = ptbits >> 3;
  if( ptbits % 8 ) ptbytes++;
  mpz_import(m, ptbytes, 1, 1, 1, 0, message);

  /**********************CRT*************************/

  mpz_powm(s1, m, rsa->dmp1, rsa->p);
  mpz_powm(s2, m, rsa->dmq1, rsa->q);

  if( mpz_cmp(s1, s2) < 0 )
    mpz_add(s1, s1, rsa->p);
  mpz_sub(h, s1, s2);
  mpz_mul(h, h, rsa->iqmp);
  mpz_mod(h, h, rsa->p);

  mpz_mul(s, rsa->q, h);
  mpz_add(s, s, s2);

  /* We can also calculate s the traditional way: */
  /* mpz_powm(s, m, rsa->d, rsa->n); */

  /**************************************************/

  ctbits = mpz_sizeinbase(s, 2);
  ctbytes = ctbits >> 3;
  if( ctbits % 8 ) ctbytes++;
  diff = ptbytes-ctbytes;
  for(i = 0; i < diff; i++) signature[i] = 0;
  mpz_export(signature+diff, NULL, 1, 1, 1, 0, s);

  mpz_clear(s2);
  mpz_clear(s1);
  mpz_clear(s);
  mpz_clear(h);
  mpz_clear(m);
}
