/*

  Copyright (c) 2015 Martin Sustrik

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"),
  to deal in the Software without restriction, including without limitation

  the rights to use, copy, modify, merge, publish, distribute, sublicense,
  and/or sell copies of the Software, and to permit persons to whom
  the Software is furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
  IN THE SOFTWARE.

*/

#include <assert.h>
#include <ctype.h>
#include <libmill.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "base64.h"
#include "wsock.h"

struct wsock {
    tcpsock u;
};

/* Gets one CRLF-delimited line from the socket. Trims all leading and trailing
   whitesepace. Replaces any remaining whitespace sequences by single space. */
static int wsockgetline(wsock s, char *buf, size_t len, int64_t deadline) {
    size_t sz = tcprecvuntil(s->u, buf, len, "\r", 1, deadline);
    if(errno != 0)
        return -1;
    sz--;
    char c;
    tcprecv(s->u, &c, 1, deadline);
    if(errno != 0)
        return -1;
    if(c != '\n') {
        errno = EPROTO;
        return -1;
    }
    size_t i;
    for(i = 0; i != sz; ++i) {
        if(buf[i] < 32 || buf[i] > 127) {
            errno = EPROTO;
            return -1;
        }
    }
    i = 0;
    while(i != sz && isspace(buf[i]))
        ++i;
    size_t pos = 0;
    while(i != sz) {
        if(isspace(buf[i])) {
            while(i != sz && isspace(buf[i]))
                ++i;
            --i;
        }
        buf[pos++] = buf[i++];
    }
    if(pos && isspace(buf[pos - 1]))
        --pos;
    return pos;
}

wsock wsocklisten(ipaddr addr, int backlog) {
    struct wsock *s = (struct wsock*)malloc(sizeof(struct wsock));
    if(!s) {
        errno = ENOMEM;
        return NULL;
    }
    s->u = tcplisten(addr, backlog);
    if(!s->u) {
        free(s);
        return NULL;
    }
    return s;
}

wsock wsockaccept(wsock s, int64_t deadline) {
    struct wsock *as = (struct wsock*)malloc(sizeof(struct wsock));
    as->u = tcpaccept(s->u, deadline);
    if(errno != 0) {
        free(as);
        return NULL;
    }
    char buf[256];
    size_t sz = wsockgetline(as, buf, sizeof(buf), deadline);
    if(sz < 0) {
        tcpclose(as->u);
        free(as);
        return NULL;
    }
    char *lend = buf + sz;
    char *wstart = buf;
    char *wend = (char*)memchr(buf, ' ', lend - wstart);
    if(!wend || wend - wstart != 3 || memcmp(wstart, "GET", 3) != 0) {
        tcpclose(as->u);
        free(as);
        errno = EPROTO;
        return NULL;
    }
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(!wend) {
        tcpclose(as->u);
        free(as);
        errno = EPROTO;
        return NULL;
    }
    // TODO: Store the URL.
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(wend || lend - wstart != 8 || memcmp(wstart, "HTTP/1.1", 8) != 0) {
        tcpclose(as->u);
        free(as);
        errno = EPROTO;
        return NULL;
    }
    // Parse individual fields.
    while(1) {
        sz = wsockgetline(as, buf, sizeof(buf), deadline);
        if(sz < 0) {
            tcpclose(as->u);
            free(as);
            return NULL;
        }
        if(sz == 0)
            break;
        // TODO
    }

    assert(0);
}

wsock wsockconnect(ipaddr addr, const char *url, int64_t deadline) {
    struct wsock *s = (struct wsock*)malloc(sizeof(struct wsock));
    if(!s) {
        errno = ENOMEM;
        return NULL;
    }
    s->u = tcpconnect(addr, deadline);
    if(errno != 0) {
        free(s);
        return NULL;
    }
    tcpsend(s->u, "GET ", 4, deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    tcpsend(s->u, url, strlen(url), deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    const char *lit1 =
        " HTTP/1.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: ";
    tcpsend(s->u, lit1, strlen(lit1), deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    struct timeval tv;
    if(gettimeofday(&tv, NULL) == -1) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    srandom((int)tv.tv_usec);
    uint8_t nonce[16];
    int i;
    for(i = 0; i != 16; ++i)
        nonce[i] = random() % 256;
    char swsk[32];
    int swsk_len = wsock_base64_encode(nonce, 16, swsk, sizeof(swsk));
    assert(swsk_len > 0);
    tcpsend(s->u, swsk, swsk_len, deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    tcpsend(s->u, "\r\n\r\n", 4, deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }
    tcpflush(s->u, deadline);
    if(errno != 0) {
        tcpclose(s->u);
        free(s);
        return NULL;
    }

    msleep(now() + 1000);
    assert(0);
}

const char *wsockurl(wsock s) {
    assert(0);
}

size_t wsocksend(wsock s, const void *msg, size_t len) {
    assert(0);
}

size_t wsockrecv(wsock s, void *msg, size_t len) {
    assert(0);
}

void wsockclose(wsock s) {
    assert(0);
}

