/*

  Copyright (c) 2015 Martin Sustrik  All rights reserved

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
#include <libmill.h>
#include <string.h>

#include "../wsock.h"

coroutine void client(void) {
    ipaddr addr = ipremote("127.0.0.1", 5555, 0, -1);
    wsock s = wsockconnect(addr, NULL, "/", -1);
    assert(s);

    /* Send ping, get pong. */
    wsockping(s, -1);
    assert(errno == 0);
    size_t sz = wsockrecv(s, NULL, 0, -1);
    assert(sz == 0 && errno == EAGAIN);

    /* Send unsolicited pong. */
    wsockpong(s, -1);
    assert(errno == 0);

    /* A normal message. */
    sz = wsocksend(s, "ABC", 3, -1);
    assert(sz == 3);

    wsockclose(s);
}

int main() {
    ipaddr addr = iplocal("127.0.0.1", 5555, 0);

    wsock ls = wsocklisten(addr, NULL, 10);
    assert(ls);
    go(client());
    wsock s = wsockaccept(ls, -1);
    assert(s);

    /* Receive the unsolicited pong. */
    size_t sz = wsockrecv(s, NULL, 0, -1);
    assert(sz == 0 && errno == EAGAIN);

    /* Receive the normal message. */
    char buf[3];
    sz = wsockrecv(s, buf, sizeof(buf), -1);
    assert(sz == 3);
    assert(memcmp(buf, "ABC", 3) == 0);

    wsockclose(s);
    wsockclose(ls);

    return 0;
}

