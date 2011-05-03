#ifndef _EMSA_PSS_H
#define _EMSA_PSS_H

typedef struct _rsa_t {
  mpz_t n;      // public modulus
  mpz_t e;      // public exponent
  mpz_t d;      // private exponent
  mpz_t p;      // secret prime factor
  mpz_t q;      // secret prime factor
  mpz_t dmp1;   // d mod (p-1)
  mpz_t dmq1;   // d mod (q-1)
  mpz_t iqmp;   // q^-1 mod p
} rsa_t;

typedef struct _datum_t {
  uint8_t *data;
  uint32_t size;
} datum_t;

int32_t emsa_pss_encode(datum_t *em, rsa_t *rsa, datum_t *m);
int32_t emsa_pss_verify(uint8_t *em, rsa_t *rsa, datum_t *m);

void rsa_init(rsa_t *rsa);
void rsa_free(rsa_t *rsa);
void rsasp1(uint8_t *signature, uint8_t *message, rsa_t *rsa);

#endif /* _EMSA_PSS_H */
