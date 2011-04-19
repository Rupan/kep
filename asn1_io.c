/*

Some initial work on ASN.1 parsing
License: GPL3

*/

#include <stdio.h>

/* file i/o */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "RSAPrivateKey.h"
#include "DHParameter.h"

typedef struct _datum_t {
  unsigned char *data;
  unsigned int size;
} datum_t;

static int slurp(const char *path, datum_t *datum) {
  int fd, ret;
  ssize_t bytes;
  struct stat path_stat;

  fd = open(path, O_RDONLY);
  if( fd == -1 ) return -1;
  ret = fstat(fd, &path_stat);
  if( ret == -1 ) {
    close(fd);
    return -1;
  }
  datum->data = malloc(path_stat.st_size);
  if( datum->data == NULL ) {
    close(fd);
    return -1;
  }
  datum->size = (unsigned int)path_stat.st_size;
  bytes = read(fd, datum->data, (size_t)datum->size);
  if( bytes != (ssize_t)path_stat.st_size ) {
    free(datum->data);
    datum->size = 0;
    close(fd);
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  int ret, i;
  datum_t der;
  asn_dec_rval_t er;
  RSAPrivateKey_t *key = NULL;
  DHParameter_t *dhm = NULL;

  if( argc != 3 ) {
    printf("Usage: %s <RSA key> <DHM param>\n", argv[0]);
    return -1;
  }

  ret = slurp(argv[1], &der);
  if( ret == -1 ) {
    printf("Unable to read RSA DER file.\n");
    return -1;
  }
  er = asn_DEF_RSAPrivateKey.ber_decoder(0, &asn_DEF_RSAPrivateKey, (void **) &key, der.data, der.size, 0);
  if(er.code != RC_OK) {
    printf("Unable to decode RSA DER data [%d].\n", er.code);
    asn_DEF_RSAPrivateKey.free_struct(&asn_DEF_RSAPrivateKey, key, 0);
    free(der.data);
    return -1;
  } else {
    /* xer_fprint(stdout, &asn_DEF_RSAPrivateKey, key); */
    for(i = 0; i < key->modulus.size; i++)
      printf("%02X", key->modulus.buf[i]);
    printf("\n");
  }

  asn_DEF_RSAPrivateKey.free_struct(&asn_DEF_RSAPrivateKey, key, 0);
  key = NULL;
  free(der.data);

  /* testing DHM parameters */

  ret = slurp(argv[2], &der);
  if( ret == -1 ) {
    printf("Unable to read DHM DER file.\n");
    return -1;
  }
  er = asn_DEF_DHParameter.ber_decoder(0, &asn_DEF_DHParameter, (void **) &dhm, der.data, der.size, 0);
  if(er.code != RC_OK) {
    printf("Unable to decode DHM DER data [%d].\n", er.code);
    asn_DEF_DHParameter.free_struct(&asn_DEF_DHParameter, dhm, 0);
    free(der.data);
    return -1;
  } else {
    xer_fprint(stdout, &asn_DEF_DHParameter, dhm);
    /*
    for(i = 0; i < dhm->prime.size; i++)
      printf("%02X", dhm->prime.buf[i]);
    printf("\n");
    */
  }
  asn_DEF_DHParameter.free_struct(&asn_DEF_DHParameter, dhm, 0);
  dhm = NULL;
  free(der.data);

  return 0;
}
