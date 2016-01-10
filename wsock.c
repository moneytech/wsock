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

#include "base64.h"
#include "random.h"
#include "sha1.h"
#include "str.h"
#include "wire.h"
#include "wsock.h"

/* 0 on connection socket, 1 on listening socket. */
#define WSOCK_LISTENING 1
/* 0 on server, 1 on client. */
#define WSOCK_CLIENT 2
/* TCP connection broken or deadline occured while sending or receiving a
   message. In such case the message is half-processed. There's no way to
   continue or even do the final handshake. */
#define WSOCK_BROKEN 4
/* Set if wsockdone() was already called. */
#define WSOCK_DONE 8

/* Used when hashing WebSocket keys. See RFC 6455, chapter 4. */
static const char *wsock_uuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct wsock {
    tcpsock u;
    int flags;
    struct wsock_str url;
    struct wsock_str subprotocol;
};

/* Gets one CRLF-delimited line from the socket. Trims all leading and trailing
   whitesepace. Replaces any remaining whitespace sequences by single space. */
static int wsock_getline(wsock s, char *buf, size_t len, int64_t deadline) {
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

static const char *wsock_hassubprotocol(const char *available,
      const char *requested, size_t rqsz, size_t *ressz) {
    /* This algorithm has quadratic complexity but we assume the list of
       subprotocols is short, so we don't care. */
    /* Walk through all requested subprotocols. */
    while(rqsz) {
        size_t rsz = 0;
        while(rqsz && requested[rsz] != ',')
            ++rsz, --rqsz;
        if(rqsz)
            --rqsz;
        /* Walk through all the available subprotocols. */
        const char *av = available;
        while(av[0]) {
            size_t asz = 0;
            while(av[asz] != 0 && av[asz] != ',')
                ++asz;
            if(rsz == asz && memcmp(requested, av, asz) == 0) {
                if(ressz)
                    *ressz = asz;
                return av;
            }
            av += asz + 1;
        }
        requested += rsz + 1;
    }
    return NULL;
}

static int wsock_checkstring(const char *s) {
    if(s) {
        int i = 0;
        while(s[i]) {
            if(s[i] < 32 || s[i] > 127) {errno = EINVAL; return 0;}
            ++i;
        }
        if(i == 0) {errno = EINVAL; return 0;}
    }
    errno = 0;
    return 1;
}

wsock wsocklisten(ipaddr addr, const char *subprotocol, int backlog) {
    /* Check the arguments. */
    if(!wsock_checkstring(subprotocol))
        return NULL;

    struct wsock *s = (struct wsock*)malloc(sizeof(struct wsock));
    if(!s) {errno = ENOMEM; return NULL;}
    s->flags = WSOCK_LISTENING;
    s->u = tcplisten(addr, backlog);
    if(!s->u) {free(s); return NULL;}
    wsock_str_init(&s->url, NULL, 0);
    wsock_str_init(&s->subprotocol, subprotocol, wsock_str_len(subprotocol));
    return s;
}

wsock wsockaccept(wsock s, int64_t deadline) {
    int err = 0;
    if(!(s->flags & WSOCK_LISTENING)) {err = EOPNOTSUPP; goto err0;}
    struct wsock *as = (struct wsock*)malloc(sizeof(struct wsock));
    if(!as) {err = ENOMEM; goto err0;}
    as->flags = 0;
    as->u = tcpaccept(s->u, deadline);
    if(errno != 0) {err = errno; goto err1;}
    wsock_str_init(&as->url, NULL, 0);
    wsock_str_init(&as->subprotocol, NULL, 0);

    /* Parse request. */
    char buf[256];
    size_t sz = wsock_getline(as, buf, sizeof(buf), deadline);
    if(sz < 0) {err = errno; goto err2;}
    char *lend = buf + sz;
    char *wstart = buf;
    char *wend = (char*)memchr(buf, ' ', lend - wstart);
    if(!wend || wend - wstart != 3 || memcmp(wstart, "GET", 3) != 0) {
        err = EPROTO; goto err2;}
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(!wend) {err = EPROTO; goto err2;}
    wsock_str_init(&as->url, wstart, wend - wstart);
    wstart = wend + 1;
    wend = (char*)memchr(wstart, ' ', lend - wstart);
    if(wend || lend - wstart != 8 || memcmp(wstart, "HTTP/1.1", 8) != 0) {
        err = EPROTO; goto err2;}
    int hasupgrade = 0;
    int hasconnection = 0;
    int haskey = 0;
    int seensubprotocol = 0;
    int hassubprotocol = 0;
    const char *subprotocol = NULL;
    size_t subprotocolsz = 0;
    struct wsock_sha1 sha1;
    while(1) {
        sz = wsock_getline(as, buf, sizeof(buf), deadline);
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
        /* TODO: Trim trailing whitespace */
        size_t vsz = lend - vstart;
        if(nsz == 7 && strncasecmp(nstart, "Upgrade", 7) == 0) {
            if(hasupgrade || vsz != 9 || memcmp(vstart, "websocket", 9) != 0) {
                err = EPROTO; goto err2;}
            hasupgrade = 1;
            continue;
        }
        if(nsz == 10 && strncasecmp(nstart, "Connection", 10) == 0) {
            if(hasconnection || vsz != 7 || memcmp(vstart, "Upgrade", 7) != 0) {
                err = EPROTO; goto err2;}
            hasconnection = 1;
            continue;
        }
        if(nsz == 17 && strncasecmp(nstart, "Sec-WebSocket-Key", 17) == 0) {
            if(haskey) {err = EPROTO; goto err2;}
            wsock_sha1_init(&sha1);
            int i;
            for(i = 0; i != vsz; ++i)
                wsock_sha1_hashbyte(&sha1, vstart[i]);
            for(i = 0; i != 36; ++i)
                wsock_sha1_hashbyte(&sha1, wsock_uuid[i]);
            haskey = 1;
            continue;
        }
        if(nsz == 22 &&
              strncasecmp(nstart, "Sec-WebSocket-Protocol", 22) == 0) {
            seensubprotocol = 1;
            /* RFC6455, section 11.3.4 allows for multiple instances of
               this field. Therefore we are going to ignore it once we have
               a subprotocol selected. */
            if(!hassubprotocol) {
                const char *available = wsock_str_get(&s->subprotocol);
                if(available) {
                    subprotocol = wsock_hassubprotocol(available, vstart, vsz,
                        &subprotocolsz);
                    /* No matching subprotocol? Never mind, there may be one
                       present in following instance of this field. */
                    if(!subprotocol)
                        continue;
                }
                else {
                    subprotocol = vstart;
                    subprotocolsz = vsz;
                }
                hassubprotocol = 1;
                wsock_str_init(&as->subprotocol, subprotocol, subprotocolsz);
            }
            continue;
        }
    }
    if(!hasupgrade || !hasconnection || !haskey) {err = EPROTO; goto err2;}
    if(seensubprotocol && !hassubprotocol) {err = EPROTO; goto err2;}

    /* If the subprotocol was not specified by the client, we still want to
       use one of the suerver-supported protocols locally. */
    if(!subprotocol) {
        const char *available = wsock_str_get(&s->subprotocol);
        if(available) {
            size_t asz = 0;
            while(available[asz] != 0 && available[asz] != ',')
                ++asz;
            wsock_str_init(&as->subprotocol, available, asz);
        }
    }

    /* Send reply. */
    const char *lit1 =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: ";
    tcpsend(as->u, lit1, strlen(lit1), deadline);
    if(errno != 0) {err = errno; goto err2;}
    char key[32];
    sz = wsock_base64_encode(wsock_sha1_result(&sha1), 20, key, sizeof(key));
    assert(sz > 0);
    tcpsend(as->u, key, sz, deadline);
    if(errno != 0) {err = errno; goto err2;}
    if(hassubprotocol) {
        tcpsend(as->u, "\r\nSec-WebSocket-Protocol: ", 26, deadline);
        if(errno != 0) {err = errno; goto err2;}
        tcpsend(as->u, subprotocol, subprotocolsz, deadline);
        if(errno != 0) {err = errno; goto err2;}
    }
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

wsock wsockconnect(ipaddr addr, const char *subprotocol, const char *url,
      int64_t deadline) {
    /* Check the arguments. */
    if(!wsock_checkstring(url))
        return NULL;
    if(subprotocol) {
        if(!wsock_checkstring(subprotocol))
        return NULL;
    }

    /* Open TCP connection. */
    int err = 0;
    struct wsock *s = (struct wsock*)malloc(sizeof(struct wsock));
    if(!s) {err = ENOMEM; goto err0;}
    s->flags = WSOCK_CLIENT;
    s->u = tcpconnect(addr, deadline);
    if(errno != 0) {err = errno; goto err1;}
    wsock_str_init(&s->url, url, strlen(url));
    wsock_str_init(&s->subprotocol, NULL, 0);

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
    uint32_t nonce[4];
    int i;
    for(i = 0; i != 4; ++i)
        nonce[i] = wsock_random();
    char swsk[32];
    int swsksz = wsock_base64_encode((uint8_t*)nonce, sizeof(nonce),
        swsk, sizeof(swsk));
    assert(swsksz > 0);
    tcpsend(s->u, swsk, swsksz, deadline);
    if(errno != 0) {err = errno; goto err2;}
    if(subprotocol) {
        tcpsend(s->u, "\r\nSec-WebSocket-Protocol: ", 26, deadline);
        if(errno != 0) {err = errno; goto err2;}
        tcpsend(s->u, subprotocol, strlen(subprotocol), deadline);
        if(errno != 0) {err = errno; goto err2;}
    }
    tcpsend(s->u, "\r\n\r\n", 4, deadline);
    if(errno != 0) {err = errno; goto err2;}
    tcpflush(s->u, deadline);
    if(errno != 0) {err = errno; goto err2;}

    /* Parse reply. */
    char buf[256];
    size_t sz = wsock_getline(s, buf, sizeof(buf), deadline);
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
    int hassubprotocol = 0;
    while(1) {
        sz = wsock_getline(s, buf, sizeof(buf), deadline);
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
        /* TODO: Trim trailing whitespace. */
        size_t vsz = lend - vstart;
        if(nsz == 7 && strncasecmp(nstart, "Upgrade", 7) == 0) {
            if(hasupgrade || vsz != 9 || memcmp(vstart, "websocket", 9) != 0) {
                err = EPROTO; goto err2;}
            hasupgrade = 1;
            continue;
        }
        if(nsz == 10 && strncasecmp(nstart, "Connection", 10) == 0) {
            if(hasconnection || vsz != 7 || memcmp(vstart, "Upgrade", 7) != 0) {
                err = EPROTO; goto err2;}
            hasconnection = 1;
            continue;
        }
        if(nsz == 20 && strncasecmp(nstart, "Sec-WebSocket-Accept", 20) == 0) {
            if(haskey) {err = EPROTO; goto err2;}
            /* Compute the expected value of the key. */
            struct wsock_sha1 sha1;
            wsock_sha1_init(&sha1);
            for(i = 0; i != swsksz; ++i)
                wsock_sha1_hashbyte(&sha1, swsk[i]);
            for(i = 0; i != 36; ++i)
                wsock_sha1_hashbyte(&sha1, wsock_uuid[i]);
            char key[32];
            size_t keysz = wsock_base64_encode(wsock_sha1_result(&sha1), 20,
                key, sizeof(key));
            assert(sz > 0);
            /* Check whether the received key matches the expected one. */
            if(vsz != keysz || memcmp(vstart, key, vsz) != 0) {
                err = EPROTO; goto err2;}
            haskey = 1;
            continue;
        }
        if(nsz == 22 &&
              strncasecmp(nstart, "Sec-WebSocket-Protocol", 22) == 0) {
            if(hassubprotocol) {err = EPROTO; goto err2;}
            for(i = 0; i != vsz; ++i)
                if(vstart[i] == ',') {err = EPROTO; goto err2;}
            if(!wsock_hassubprotocol(subprotocol, vstart, vsz, NULL)) {
                err = EPROTO; goto err2;}
            wsock_str_init(&s->subprotocol, vstart, vsz);
            hassubprotocol = 1;
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
    return wsock_str_get(&s->url);
}

const char *wsocksubprotocol(wsock s) {
    return wsock_str_get(&s->subprotocol);
}

size_t wsocksend(wsock s, const void *msg, size_t len, int64_t deadline) {
    if(s->flags & WSOCK_LISTENING) {errno = EOPNOTSUPP; return 0;}
    if(s->flags & WSOCK_BROKEN) {errno = ECONNABORTED; return 0;}
    uint8_t buf[12];
    size_t sz;
    buf[0] = 0x82;
    if(len > 0xffff) {
        buf[1] = 127;
        wsock_putll(buf + 2, len);
        sz = 10;
    }
    else if(len > 125) {
        buf[1] = 126;
        wsock_puts(buf + 2, len);
        sz = 4;
    }
    else {
        buf[1] = (uint8_t)len;
        sz = 2;
    }
    uint8_t mask[4];
    if(s->flags & WSOCK_CLIENT) {
        *((uint32_t*)mask) = wsock_random();
        buf[1] |= 0x80;
        memcpy(buf + sz, mask, 4);
        sz += 4;
    }
    tcpsend(s->u, buf, sz, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
    if(s->flags & WSOCK_CLIENT) {
        /* TODO: Use static buffer or something. This way of implementing
           mapping is performance nightmare. */
        uint8_t *masked = malloc(len);
        if(!masked) {s->flags |= WSOCK_BROKEN; errno = ENOMEM; return 0;}
        size_t i;
        for(i = 0; i != len; ++i)
            masked[i] = ((uint8_t*)msg)[i] ^ mask[i % 4];
        tcpsend(s->u, masked, len, deadline);
        int err = errno;
        free(masked);
        errno = err;
    }
    else {
        tcpsend(s->u, msg, len, deadline);
    }
    if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
    tcpflush(s->u, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
    return len;
}

size_t wsockrecv(wsock s, void *msg, size_t len, int64_t deadline) {
    if(s->flags & WSOCK_LISTENING) {errno = EOPNOTSUPP; return 0;}
    if(s->flags & WSOCK_BROKEN) {errno = ECONNABORTED; return 0;}
    size_t res = 0;
    while(1) {
        uint8_t hdr1[2];
        tcprecv(s->u, hdr1, 2, deadline);
        if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
        if(hdr1[0] & 0x70) {
            s->flags &= WSOCK_BROKEN; errno = EPROTO; return 0;}
        int opcode = hdr1[0] & 0x0f;
        if(opcode == 8) {
            if(!(s->flags & WSOCK_DONE)) {
                /* TODO: Close frames from client should be masked. */
                tcpsend(s->u, "\x88\x00", 2, deadline);
                tcpflush(s->u, deadline);
                s->flags |= (WSOCK_BROKEN & WSOCK_DONE);
            }
            errno = ECONNRESET;
            return 0;
        }
        if(opcode == 9) {
            /* TODO: Account for pings and pongs with payload. */
            if(!(s->flags & WSOCK_DONE)) {
                tcpsend(s->u, "\x8A\x00", 2, deadline);
                if(errno != 0) {s->flags &= WSOCK_BROKEN; return 0;}
                tcpflush(s->u, deadline);
                if(errno != 0) {s->flags &= WSOCK_BROKEN; return 0;}
            }
            continue;
        }
        if(opcode == 10) {
            /* TODO: Account for pings and pongs with payload. */
            /* TODO: Do we want to make exiting the function here optional? */
            errno = EAGAIN;
            return 0;
        }
        if(!!(s->flags & WSOCK_CLIENT) ^ !(hdr1[1] & 0x80)) {
            s->flags &= WSOCK_BROKEN; errno = EPROTO; return 0;}
        size_t sz = hdr1[1] & 0x7f;
        if(sz == 126) {
            uint8_t hdr2[2];
            tcprecv(s->u, hdr2, 2, deadline);
            if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
            sz = wsock_gets(hdr2);
        }
        else if(sz == 127) {
            uint8_t hdr2[8];
            tcprecv(s->u, hdr2, 8, deadline);
            if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
            sz = wsock_getll(hdr2);
        }
        uint8_t mask[4];
        if(!(s->flags & WSOCK_CLIENT)) {
            tcprecv(s->u, mask, 4, deadline);
            if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
        }
        size_t toread = sz < len ? sz : len;
        if(toread > 0) {
            tcprecv(s->u, msg, toread, deadline);
            if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
        }
        if(!(s->flags & WSOCK_CLIENT)) {
            size_t i;
            for(i = 0; i != toread; ++i)
                ((uint8_t*)msg)[i] ^= mask[i % 4];
        }
        if(sz > toread) {
            tcprecv(s->u, NULL, sz - toread, deadline);
            if(errno != 0) {s->flags |= WSOCK_BROKEN; return 0;}
        }
        res += sz;
        if(hdr1[0] & 0x80)
            break;
        msg = ((uint8_t*)msg) + sz;
        len -= sz;
    }
    return res;
}

void wsockping(wsock s, int64_t deadline) {
    if(s->flags & WSOCK_LISTENING) {errno = EOPNOTSUPP; return;}
    if(s->flags & (WSOCK_BROKEN | WSOCK_DONE)) {errno = ECONNABORTED; return;}
    tcpsend(s->u, "\x89\x00", 2, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN;}
    tcpflush(s->u, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN;}
    errno = 0;
}

void wsockpong(wsock s, int64_t deadline) {
    if(s->flags & WSOCK_LISTENING) {errno = EOPNOTSUPP; return;}
    if(s->flags & (WSOCK_BROKEN | WSOCK_DONE)) {errno = ECONNABORTED; return;}
    tcpsend(s->u, "\x8A\x00", 2, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN;}
    tcpflush(s->u, deadline);
    if(errno != 0) {s->flags |= WSOCK_BROKEN;}
    errno = 0;
}

void wsockdone(wsock s, int64_t deadline) {
    if(s->flags & WSOCK_LISTENING) {errno = EOPNOTSUPP; return;}
    if(s->flags & WSOCK_BROKEN) {errno = ECONNABORTED; return;}
    if(!(s->flags & WSOCK_DONE)) {
        if(s->flags & WSOCK_DONE) {errno = EPROTO; return;}
        tcpsend(s->u, "\x88\x00", 2, deadline);
        if(errno != 0) {s->flags |= WSOCK_BROKEN;}
        tcpflush(s->u, deadline);
        if(errno != 0) {s->flags |= WSOCK_BROKEN;}
        s->flags |= WSOCK_DONE;
    }
    errno = 0;
}

void wsockclose(wsock s) {
    assert(s->u);
    tcpclose(s->u);
    wsock_str_term(&s->url);
    wsock_str_term(&s->subprotocol);
    free(s);
}

