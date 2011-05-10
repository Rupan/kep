/*
  Function signatures and data types for Brian Gladman's SHA modules
  which are compatible with code in this directory.
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

#ifndef _BRG_SHA_H
#define _BRG_SHA_H

#include <inttypes.h>

#if defined(USE_SHA1)

typedef struct _sha1_ctx {
    uint32_t count[2];
    uint32_t hash[5];
    uint32_t wbuf[16];
} sha1_ctx;

void sha1_begin(/*@out@*/ sha1_ctx *ctx);
void sha1_hash(const uint8_t *data, uint32_t len, sha1_ctx *ctx);
void sha1_end(/*@out@*/ uint8_t *hval, sha1_ctx *ctx);

#else /* USE_SHA1 */

typedef struct _sha256_ctx {
    uint32_t count[2];
    uint32_t hash[8];
    uint32_t wbuf[16];
} sha256_ctx;

void sha256_begin(/*@out@*/ sha256_ctx *ctx);
void sha256_hash(const uint8_t *data, uint32_t len, sha256_ctx *ctx);
void sha256_end(/*@out@*/ uint8_t *hval, sha256_ctx *ctx);

#endif /* USE_SHA1 */

#endif /* _BRG_SHA_H */
