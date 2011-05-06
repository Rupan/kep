/*
License: GPL3.
This program will (eventually) import RSA private keys into an SQLite database.
This might be useful on e.g. Android, for the KEP subroutines.
*/

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

typedef struct _datum_t {
  uint8_t *data;
  uint32_t size;
} datum_t;

const char *add_tbl = "CREATE TABLE IF NOT EXISTS private_key ( name TEXT PRIMARY KEY ASC NOT NULL, n BLOB NOT NULL, e BLOB NOT NULL, d BLOB NOT NULL, p BLOB NOT NULL, q BLOB NOT NULL, dp BLOB NOT NULL, dq BLOB NOT NULL, qinv BLOB NOT NULL );";
const char *add_key = "INSERT INTO private_key (name, n, e, d, p, q, dp, dq, qinv) VALUES (?,?,?,?,?,?,?,?,?);";

int main(int argc, char **argv) {
  int rc, i;
  RSA *pk;
  FILE *fp;
  sqlite3 *db;
  char *err;
  const char *tail;
  datum_t pk_bin[8];
  sqlite3_stmt *stmt;
  unsigned char buf[8][1024];

  if( argc != 4 ) {
    printf("Usage: %s <key> <database> <name>\n", argv[0]);
    return -1;
  }

  /*
     parse the given PEM key, from e.g.
     openssl genrsa -out testkey.pem 2048
  */
  fp = fopen(argv[1], "r");
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

  for(i=0; i<8; i++)
    pk_bin[i].data = buf[i];

  pk_bin[0].size = BN_num_bytes(pk->n);
  if( pk_bin[0].size > 1024 ) {
    printf("Private key too large (8192 bits max).\n");
    RSA_free(pk);
    sqlite3_close(db);
    return -1;
  }
  BN_bn2bin(pk->n, pk_bin[0].data);
  pk_bin[1].size = BN_num_bytes(pk->e);
  BN_bn2bin(pk->e, pk_bin[1].data);
  pk_bin[2].size = BN_num_bytes(pk->d);
  BN_bn2bin(pk->d, pk_bin[2].data);
  pk_bin[3].size = BN_num_bytes(pk->p);
  BN_bn2bin(pk->p, pk_bin[3].data);
  pk_bin[4].size = BN_num_bytes(pk->q);
  BN_bn2bin(pk->q, pk_bin[4].data);
  pk_bin[5].size = BN_num_bytes(pk->dmp1);
  BN_bn2bin(pk->dmp1, pk_bin[5].data);
  pk_bin[6].size = BN_num_bytes(pk->dmq1);
  BN_bn2bin(pk->dmq1, pk_bin[6].data);
  pk_bin[7].size = BN_num_bytes(pk->iqmp);
  BN_bn2bin(pk->iqmp, pk_bin[7].data);

  RSA_free(pk);

  /* open & update the specified sqlite database */
  rc = sqlite3_open(argv[2], &db);
  if( rc != SQLITE_OK ) {
    sqlite3_close(db);
    printf("Unable to open SQLite database.\n");
    return -1;
  }

  rc = sqlite3_exec(db, add_tbl, NULL, NULL, &err);
  if( rc != SQLITE_OK ) {
    fprintf(stderr, "Failed to initialize 'private' table [%s]\n", err);
    sqlite3_free(err);
    sqlite3_close(db);
    return -1;
  }

  rc = 0;
  sqlite3_prepare_v2(db, add_key, strlen(add_key)+1, &stmt, &tail);
  sqlite3_bind_text(stmt, 1, argv[3], strlen(argv[3]), SQLITE_TRANSIENT);
  for(i=0; i<8; i++)
    sqlite3_bind_blob(stmt, i+2, pk_bin[i].data, pk_bin[i].size, SQLITE_TRANSIENT);
  if( sqlite3_step(stmt) != SQLITE_DONE ) {
    printf("Unable to import RSA key (%s); a unique name must be provided.\n", sqlite3_errmsg(db));
    rc = 1;
  }
  sqlite3_clear_bindings(stmt);
  sqlite3_reset(stmt);
  sqlite3_finalize(stmt);

  sqlite3_close(db);

  return 0;
}
