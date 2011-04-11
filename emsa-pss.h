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

int32_t emsa_pss_encode(uint8_t *em, uint32_t emBits, uint8_t *m, uint32_t mBytes);
int32_t emsa_pss_verify(uint8_t *em, uint32_t emBits, uint8_t *m, uint32_t mBytes);

void rsa_init(rsa_t *rsa);
void rsa_free(rsa_t *rsa);
void rsasp1(uint8_t *signature, uint8_t *message, rsa_t *rsa);

#endif /* _EMSA_PSS_H */
