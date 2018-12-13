/*
 * Copyright (c) 2015-2016 Yubico AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef DEBUG_H
#define DEBUG_H

#define YKCS11_DBG 1
#define YKCS11_DINOUT 1

#define PROGNAME "nerveskey_pkcs11"

#define UNIMPLEMENTED() do { \
fprintf(stderr, "%s: %s is unimplemented.\r\n", PROGNAME, __func__); \
} while (0)


#define D(x...) do {                                                           \
    fprintf (stderr, "debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    fprintf (stderr, x);                                                       \
    fprintf (stderr, "\r\n");                                                    \
  } while (0)

#if YKCS11_DBG
#include <stdio.h>
#define DBG(x...) D(x);
#else
#define DBG(x...)
#endif

#if YKCS11_DINOUT
#define DIN D(("In"));
#define DOUT D(("Out"));
#else
#define DIN
#define DOUT
#endif

#endif
