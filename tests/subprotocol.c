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

#include "../str.c"

coroutine void client(const char *requested, const char *expected) {
    ipaddr addr = ipremote("127.0.0.1", 5555, 0, -1);
    wsock s = wsockconnect(addr, requested, "/", -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), expected));
    wsockclose(s);
}

int main() {
    ipaddr addr = iplocal("127.0.0.1", 5555, 0);

    /* No subprotocols used. */
    wsock ls = wsocklisten(addr, NULL, 10);
    assert(ls);
    go(client(NULL, NULL));
    wsock s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), NULL));
    wsockclose(s);
    wsockclose(ls);

    /* Subprotocol used by client but not by server. */
    ls = wsocklisten(addr, NULL, 10);
    assert(ls);
    go(client("sp1", "sp1"));
    s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), "sp1"));
    wsockclose(s);
    wsockclose(ls);

    /* Subprotocol used by server but not by client. */
/*
    ls = wsocklisten(addr, "sp1", 10);
    assert(ls);
    go(client(NULL, NULL));
    s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), "sp1"));
    wsockclose(s);
    wsockclose(ls);
*/

    /* Same subprotocol used by both server and client. */
    ls = wsocklisten(addr, "sp1", 10);
    assert(ls);
    go(client("sp1", "sp1"));
    s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), "sp1"));
    wsockclose(s);
    wsockclose(ls);

    /* Client selecting one of the server's subprotocols. */
    ls = wsocklisten(addr, "sp1,sp2,sp3", 10);
    assert(ls);
    go(client("sp2", "sp2"));
    s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), "sp2"));
    wsockclose(s);
    wsockclose(ls);

    /* Client asking for subprotocol not supported by server. */
/*
    ls = wsocklisten(addr, "sp1,sp2,sp3", 10);
    assert(ls);
    go(client("sp4", "sp4"));
    wsockclose(s);
    wsockclose(ls);
*/

    /* Client selecting two of the server's subprotocols. First one should
       be preferred by the server. */
    ls = wsocklisten(addr, "sp1,sp2,sp3", 10);
    assert(ls);
    go(client("sp2,sp1", "sp2"));
    s = wsockaccept(ls, -1);
    assert(s);
    assert(wsock_str_eq(wsocksubprotocol(s), "sp2"));
    wsockclose(s);
    wsockclose(ls);

    return 0;
}

