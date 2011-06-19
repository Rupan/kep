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

/* for fill_random */
#if !defined(TEST_VECTORS)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif /* TEST_VECTORS */

/* for apply_mask */
#include <endian.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <gmp.h>
#include "pkcs1.h"
#include "brg-sha.h"

/*
  These macros depend on Brian Gladman's SHA code found here:
  http://gladman.plushost.co.uk/oldsite/cryptography_technology/sha/index.php
  To compile this source code, you need to link with sha1.c or sha2.c
  (respectively) from the source distribution above.
*/
#if defined(USE_SHA1)
#define HASH_DIGEST_SIZE 20
#define HASH_CONTEXT sha1_ctx
#define HASH_STARTS(ctx) sha1_begin(ctx)
#define HASH_UPDATE(ctx, input, ilen) sha1_hash((input), (ilen), (ctx))
#define HASH_FINISH(ctx, output) sha1_end((output), (ctx))
#else
#define HASH_DIGEST_SIZE 32
#define HASH_CONTEXT sha256_ctx
#define HASH_STARTS(ctx) sha256_begin(ctx)
#define HASH_UPDATE(ctx, input, ilen) sha256_hash((input), (ilen), (ctx))
#define HASH_FINISH(ctx, output) sha256_end((output), (ctx))
#endif

typedef union _icp_cast_t {
  uint32_t i;
  uint8_t c[4];
} icp_cast_t;

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

/*
  private: fill_random: write dlen random bytes to dst
  returns: 0 on success, -1 on failure
*/
#if !defined(TEST_VECTORS)
static int32_t fill_random(uint8_t *dst, uint32_t dlen) {
  int fd;
  int32_t ret;
  ssize_t bytes;

  ret = 0;
  fd = open("/dev/urandom", O_RDONLY);
  if( fd == -1 )
    return -1;
  bytes = read(fd, dst, dlen);
  if( bytes == -1 || (uint32_t)bytes != dlen )
    ret = -1;
  close(fd);

  return ret;
}
#else
int32_t fill_random(uint8_t *dst, uint32_t dlen);
#endif /* TEST_VECTORS */

static inline void free_datum(datum_t *d) {
  uint32_t i;

  for(i = 0; i < d->size; i++)
    d->data[i] = (const char)0x00;
  free(d->data);
  d->data = NULL;
  d->size = 0;
}

/* private: this function implements MGF1, the mask generation function from PKCS#1 */
static void apply_mask(uint8_t *mask, uint32_t mlen, uint8_t *seed, uint32_t slen) {
  HASH_CONTEXT ctx[1];
  icp_cast_t ibe;
  uint32_t i, j, outlen, tmp;
  uint8_t md[HASH_DIGEST_SIZE];

  outlen = 0;
  for(i=0; outlen < mlen; i++) {
    ibe.i = htobe32(i); /* I2OSP */
    HASH_STARTS(ctx);
    HASH_UPDATE(ctx, seed, slen);
    HASH_UPDATE(ctx, ibe.c, 4);
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

/*
private: RSA signature primitive 1, using the Chinese Remainder Theorem

Purpose: encrypt a message with an RSA private key and write out its signature
Notes: signature and message may be equal, if there is enough writable space.
Returns: -1 on error or the number of bytes written to signature on success

Parameters:
signature: [output] storage where the message signature will be written
message: [input] content which must be signed (an EMSA-PSS encoded data chunk)
*/
static int rsasp1(datum_t *signature, datum_t *message, rsa_t *rsa) {
  uint32_t diff, i;
  mpz_t m, h, s, s1, s2;
  size_t ptbits, ptbytes, ctbits, ctbytes;

  ptbits = mpz_sizeinbase(rsa->n, 2);
  ptbytes = ptbits >> 3;
  if( (ptbits & 7) != 0 ) ptbytes++;
  if( ptbytes > message->size ) {
    return -1;
  }

  mpz_init(m);
  mpz_init(h);
  mpz_init(s);
  mpz_init(s1);
  mpz_init(s2);

  mpz_import(m, ptbytes, 1, 1, 1, 0, message->data);

  #if 1 /* Use the Chinese Remainder Theorem to calculate s */
  mpz_powm(s1, m, rsa->dmp1, rsa->p);
  mpz_powm(s2, m, rsa->dmq1, rsa->q);

  if( mpz_cmp(s1, s2) < 0 )
    mpz_add(s1, s1, rsa->p);
  mpz_sub(h, s1, s2);
  mpz_mul(h, h, rsa->iqmp);
  mpz_mod(h, h, rsa->p);

  mpz_mul(s, rsa->q, h);
  mpz_add(s, s, s2);
  #else /* We can also calculate s the traditional way: */
  mpz_powm(s, m, rsa->d, rsa->n);
  #endif

  ctbits = mpz_sizeinbase(s, 2);
  ctbytes = ctbits >> 3;
  if( (ctbits & 7) != 0 ) ctbytes++;
  if( ctbytes > signature->size ) {
    mpz_clear(s2);
    mpz_clear(s1);
    mpz_clear(s);
    mpz_clear(h);
    mpz_clear(m);
    return -1;
  }
  diff = ptbytes-ctbytes;
  for(i = 0; i < signature->size; i++) signature->data[i] = 0;
  mpz_export(signature->data+diff, NULL, 1, 1, 1, 0, s);

  mpz_clear(s2);
  mpz_clear(s1);
  mpz_clear(s);
  mpz_clear(h);
  mpz_clear(m);

  return ptbytes;
}

/*
private: RSA verification primitive 1

Purpose: decrypt a signature with an RSA public key and write out its message
Notes: signature and message may be equal, if there is enough writable space.
Returns: -1 on error or the number of bytes written to message on success

Parameters:
signature: [input] the encrypted (signed) data to be decrypted
message: [output] storage for the decrypted data (an EMSA-PSS encoded data chunk)
*/
static int rsavp1(datum_t *signature, datum_t *message, rsa_t *rsa) {
  int ret;
  mpz_t s, m;
  uint32_t ctBits, ctBytes, ptBits, ptBytes, diff, i;

  ctBits = mpz_sizeinbase(rsa->n, 2);
  ctBytes = ctBits >> 3;
  if( (ctBits & 7) != 0 ) ctBytes++;
  if( ctBytes > signature->size ) {
    return -1;
  }

  mpz_init(s);
  mpz_init(m);

  mpz_import(s, ctBytes, 1, 1, 1, 0, signature->data);
  ret = mpz_cmp(s, rsa->n);
  /* "signature representative out of range" */
  if(ret >= 0 ) {
    mpz_clear(m);
    mpz_clear(s);
    return -1;
  }
  mpz_powm(m, s, rsa->e, rsa->n);
  ptBits = mpz_sizeinbase(m, 2);
  ptBytes = ptBits >> 3;
  if( ptBytes > message->size ) {
    mpz_clear(m);
    mpz_clear(s);
    return -1;
  }
  if( (ptBits & 7) != 0 ) ptBytes++;
  diff = ctBytes - ptBytes;
  for(i = 0; i < message->size; i++) message->data[i] = 0;
  mpz_export(message->data+diff, NULL, 1, 1, 1, 0, m);

  mpz_clear(m);
  mpz_clear(s);

  return ctBytes;
}

/*
  public: emsa_pss_encode: Perform EMSA-PSS signature padding (PKCS#1 v2.1)

  em     : [output] allocated storage for the message signature
           must be at least ceil(emBits/8.0) bytes long
  rsa    : [input] an allocated RSA private key with all fields filled in
           Specifically, all values for the CRT algorithm must be correct
  m      : [input] the message to be signed, size value used as message length

  Notes  : produced signature will be equal to octet length of rsa->n
           This function will overwrite the contents of em.

  Return values:
   0     : success
  -1     : insufficient output space in "em"
  -2     : "encoding error"
  -3     : fill_random failed
  -4     : signing the encoded message failed
*/

int32_t emsa_pss_encode(datum_t *em, rsa_t *rsa, datum_t *m) {
  uint32_t i, emBits, emLen, psLen, offset;
  HASH_CONTEXT ctx[1];
  uint8_t mp[8+2*HASH_DIGEST_SIZE], *p, *q;

  emBits = mpz_sizeinbase(rsa->n, 2);
  emLen = (uint32_t)(emBits/8);
  if( (emBits & 7) != 0 ) emLen++;
  if( emLen > em->size ) return -1;

  if( emLen < (2*HASH_DIGEST_SIZE + 2) )
    return -2;

  /* emsa-pss encoding is over sizeof(N)-1 bits */
  emBits--;
  if( (emBits & 7) == 0 )
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
    return -3;

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

  if( rsasp1(em, em, rsa) < 0 ) return -4;
  return 0;
}

/*
  public: emsa_pss_verify: Perform EMSA-PSS signature verification (PKCS#1 v2.1)

  em     : [input] a signature of the message in m, encoded with EMSA-PSS; an octet string
  rsa    : [input] an allocated RSA public key corresponding to the private key used to generate the signature
  m      : [input] the message to be checked against the provided signature; an octet string

  Notes: the size of 'em' can be larger than the octet length of N.  In this case only the first
         sizeof(N) bytes in 'em' will be verified.

  Return values:
    0     : success
   -1     : fatal error during initialization
   -2     : bad first or last bytes in decrypted output
   -3     : bad sentinel value after PS
   -4     : PS sentinel offset does not match dbLen
   -5     : computed hash H' does not match transmitted hash H
*/

int32_t emsa_pss_verify(datum_t *em, rsa_t *rsa, datum_t *m) {
  datum_t tmp;
  uint8_t mask;
  uint32_t i, emBits, emLen, dbLen, offset;
  HASH_CONTEXT ctx[1];
  uint8_t mp[8+2*HASH_DIGEST_SIZE], hp[HASH_DIGEST_SIZE],  *p, *q;

  /* calculate & allocate space for local storage */
  emBits = mpz_sizeinbase(rsa->n, 2);
  emLen = (uint32_t)(emBits/8);
  if( (emBits & 7) != 0 ) emLen++;
  /* is the size of the signature in em >= the octet length of N? */
  if( em->size < emLen ) return -1;
  tmp.data = malloc(emLen);
  if( tmp.data == NULL ) return -1;
  tmp.size = emLen;
  if( rsavp1(em, &tmp, rsa) < 0 ) {
    free_datum(&tmp);
    return -1;
  }

  /* emsa-pss encoding is over sizeof(N)-1 bits */
  emBits--;
  if( (emBits & 7) == 0 )
    offset = 1;
  else
    offset = 0;

  /* initial validation of decrypted input data */
  mask = ( 0xFF >> ( 8 * emLen - emBits ) );
  if( (tmp.data[0] & ~mask) != 0x00 || tmp.data[emLen-1] != 0xbc ) {
    free_datum(&tmp);
    return -2;
  }

  /* Decode DB */
  dbLen = (emLen - HASH_DIGEST_SIZE - 1);
  apply_mask(tmp.data + offset, dbLen - offset, tmp.data + dbLen, HASH_DIGEST_SIZE);
  tmp.data[0] &= mask;
  q = tmp.data;
  /* locate the sentinel value 0x01 at the end of PS */
  for(i = 0; *q == 0 && i < dbLen; i++) q++;
  if( *q++ != 0x01 ) {
    free_datum(&tmp);
    return -3;
  }
  /* q now points to the salt.  verify that the lengths match up. */
  if( (uint32_t)((q - tmp.data) + HASH_DIGEST_SIZE) != dbLen ) {
    free_datum(&tmp);
    return -4;
  }

  /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
  p = mp;
  for(i = 0; i < 8; i++) p[i] = (const char)0x00;
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

  /* compare received/decoded hash to generated hash */
  q = tmp.data + dbLen;
  for(i = 0; i < HASH_DIGEST_SIZE; i++) {
    if( q[i] != hp[i] ) {
      free_datum(&tmp);
      return -5;
    }
  }

  /* clean up and return  */
  free_datum(&tmp);
  return 0;
}
