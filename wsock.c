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
#include "sha1.h"
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
    int err = 0;
    struct wsock *as = (struct wsock*)malloc(sizeof(struct wsock));
    if(!as) {err = ENOMEM; goto err0;}
    as->u = tcpaccept(s->u, deadline);
    if(errno != 0) {err = errno; goto err1;}

    // Parse request.
    char buf[256];
    size_t sz = wsockgetline(as, buf, sizeof(buf), deadline);
    if(sz < 0) {err = errno; goto err2;}
    char *lend = buf + sz;
    char *wstart = buf;
    char *wend = (char*)memchr(buf, ' ', lend - wstart);
    if(!wend || wend - wstart != 3 || memcmp(wstart, "GET", 3) != 0) {
        err = EPROTO; goto err2;}
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(!wend) {err = EPROTO; goto err2;}
    /* TODO: Store the URL. */
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(wend || lend - wstart != 8 || memcmp(wstart, "HTTP/1.1", 8) != 0) {
        err = EPROTO; goto err2;}
    int hasupgrade = 0;
    int hasconnection = 0;
    int haskey = 0;
    struct wsock_sha1 sha1;
    while(1) {
        sz = wsockgetline(as, buf, sizeof(buf), deadline);
        if(sz < 0) {err = errno; goto err2;}
        if(sz == 0)
            break;
        lend = buf + sz;
        char *nstart = buf;
        char *nend = (char*)memchr(buf, ' ', lend - nstart);
        if(!nend || nend - nstart < 1 || nend[-1] != ':') {
            err = EPROTO; goto err2;}
        size_t nsz = nend - nstart - 1;
        char *vstart = nend + 1;
        char *vend = (char*)memchr(vstart, ' ', lend - vstart);
        if(vend) {err = EPROTO; goto err2;}
        size_t vsz = lend - vstart;
        if(nsz == 7 && memcmp(nstart, "Upgrade", 7) == 0) {
            if(hasupgrade || vsz != 9 || memcmp(vstart, "websocket", 9) != 0) {
                err = EPROTO; goto err2;}
            hasupgrade = 1;
            continue;
        }
        if(nsz == 10 && memcmp(nstart, "Connection", 10) == 0) {
            if(hasconnection || vsz != 7 || memcmp(vstart, "Upgrade", 7) != 0) {
                err = EPROTO; goto err2;}
            hasconnection = 1;
            continue;
        }
        if(nsz == 17 && memcmp(nstart, "Sec-WebSocket-Key", 17) == 0) {
            if(haskey) {err = EPROTO; goto err2;}
            wsock_sha1_init(&sha1);
            int i;
            for(i = 0; i != vsz; ++i)
                wsock_sha1_hashbyte(&sha1, vstart[i]);
            const char *uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            for(i = 0; i != 36; ++i)
                wsock_sha1_hashbyte(&sha1, uuid[i]);
            haskey = 1;
            continue;
        }
    }
    if(!hasupgrade || !hasconnection || !haskey) {err = EPROTO; goto err2;}

    /* Send reply. */
    const char *lit1 =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: ";
    tcpsend(as->u, lit1, strlen(lit1), deadline);
    if(errno != 0) {err = errno; goto err2;}
    char key[32];
    wsock_sha1_result(&sha1);
    sz = wsock_base64_encode(wsock_sha1_result(&sha1), 20, key, sizeof(key));
    assert(sz > 0);
    tcpsend(as->u, key, sz, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpsend(as->u, "\r\n\r\n", 4, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpflush(as->u, deadline);
    if(errno != 0) {err = errno; goto err2;}

    return as;

err2:
    tcpclose(as->u);
err1:
    free(as);
err0:
    errno = err;
    return NULL;
}

wsock wsockconnect(ipaddr addr, const char *url, int64_t deadline) {
    int err = 0;
    struct wsock *s = (struct wsock*)malloc(sizeof(struct wsock));
    if(!s) {err = ENOMEM; goto err0;}
    s->u = tcpconnect(addr, deadline);
    if(errno != 0) {err = errno; goto err1;}

    /* Send request. */
    tcpsend(s->u, "GET ", 4, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpsend(s->u, url, strlen(url), deadline);
    if(errno != 0) {err = errno; goto err2;}
    const char *lit1 =
        " HTTP/1.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: ";
    tcpsend(s->u, lit1, strlen(lit1), deadline);
    if(errno != 0) {err = errno; goto err2;}
    /* TODO: Set the seed once only? */
    struct timeval tv;
    if(gettimeofday(&tv, NULL) == -1) {err = errno; goto err2;}
    srandom((int)tv.tv_usec);
    uint8_t nonce[16];
    int i;
    for(i = 0; i != 16; ++i)
        nonce[i] = random() % 256;
    char swsk[32];
    int swsk_len = wsock_base64_encode(nonce, 16, swsk, sizeof(swsk));
    assert(swsk_len > 0);
    tcpsend(s->u, swsk, swsk_len, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpsend(s->u, "\r\n\r\n", 4, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpflush(s->u, deadline);
    if(errno != 0) {err = errno; goto err2;}

    /* Parse reply. */
    char buf[256];
    size_t sz = wsockgetline(s, buf, sizeof(buf), deadline);
    if(sz < 0) {err = errno; goto err2;}
    char *lend = buf + sz;
    char *wstart = buf;
    char *wend = (char*)memchr(buf, ' ', lend - wstart);
    if(!wend || wend - wstart != 8 || memcmp(wstart, "HTTP/1.1", 8) != 0) {
        err = EPROTO; goto err2;}
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(!wend || wend - wstart != 3 || memcmp(wstart, "101", 3) != 0) {
        err = EPROTO; goto err2;}
    int hasupgrade = 0;
    int hasconnection = 0;
    int haskey = 0;
    while(1) {
        sz = wsockgetline(s, buf, sizeof(buf), deadline);
        if(sz < 0) {err = errno; goto err2;}
        if(sz == 0)
            break;
        lend = buf + sz;
        char *nstart = buf;
        char *nend = (char*)memchr(buf, ' ', lend - nstart);
        if(!nend || nend - nstart < 1 || nend[-1] != ':') {
            err = EPROTO; goto err2;}
        size_t nsz = nend - nstart - 1;
        char *vstart = nend + 1;
        char *vend = (char*)memchr(vstart, ' ', lend - vstart);
        if(vend) {err = EPROTO; goto err2;}
        size_t vsz = lend - vstart;
        if(nsz == 7 && memcmp(nstart, "Upgrade", 7) == 0) {
            if(hasupgrade || vsz != 9 || memcmp(vstart, "websocket", 9) != 0) {
                err = EPROTO; goto err2;}
            hasupgrade = 1;
            continue;
        }
        if(nsz == 10 && memcmp(nstart, "Connection", 10) == 0) {
            if(hasconnection || vsz != 7 || memcmp(vstart, "Upgrade", 7) != 0) {
                err = EPROTO; goto err2;}
            hasconnection = 1;
            continue;
        }
        if(nsz == 20 && memcmp(nstart, "Sec-WebSocket-Accept", 20) == 0) {
            /* TODO */
            haskey = 1;
            continue;
        }
    }
    if(!hasupgrade || !hasconnection || !haskey) {err = EPROTO; goto err2;}

    return s;

err2:
    tcpclose(s->u);
err1:
    free(s);
err0:
    errno = err;
    return NULL;
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
    /* TODO: Closing handshake. */
    assert(s->u);
    tcpclose(s->u);
    free(s);
}

