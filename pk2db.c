/*
License: GPL3.
This program will (eventually) import RSA private keys into an SQLite database.
This might be useful on e.g. Android, for the KEP subroutines.
*/

#include <stdio.h>
#include <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

int main(int argc, char **argv) {
  int rc;
  RSA *pk;
  FILE *fp;
  sqlite3 *db;
  char fn[128];
  unsigned char buf[1024];

  if( argc != 2 ) {
    printf("Specify a base name.\n");
    return -1;
  }

  /*
     parse the given PEM key, from e.g.
     openssl genrsa -out testkey.pem 2048
  */
  snprintf(fn, sizeof(fn), "%s.pem", argv[1]);
  fp = fopen(fn, "r");
  if( fp == NULL ) {
    printf("Unable to open PEM file for reading.\n");
    return -1;
  }
  pk = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
  if( pk == NULL ) {
    fclose(fp);
    printf("Unable to parse given PEM file.\n");
    return -1;
  }
  fclose(fp);

  /* open a corresponding sqlite database */
  snprintf(fn, sizeof(fn), "%s.db", argv[1]);
  rc = sqlite3_open(fn, &db);
  if( rc != SQLITE_OK ) {
    sqlite3_close(db);
    printf("Unable to open SQLite database.\n");
    return -1;
  }

  rc = BN_num_bytes(pk->n);
  if( rc < (int)sizeof(buf) ) {
    rc = BN_bn2bin(pk->n, buf);
  }

  RSA_free(pk);
  sqlite3_close(db);

  return 0;
}
