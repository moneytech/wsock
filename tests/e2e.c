
#include <assert.h>
#include <libmill.h>
#include <string.h>

#include "../wsock.h"

coroutine void client() {
    ipaddr addr = ipremote("localhost", 5555, 0, -1);
    wsock s = wsockconnect(addr, "sp1,sp2", "/a/b/c", -1);
    assert(s);
    assert(strcmp(wsocksubprotocol(s), "sp2") == 0);
    char buf[3];
    size_t sz = wsockrecv(s, buf, sizeof(buf), -1);
    assert(errno == 0);
    assert(sz == 3);
    assert(memcmp(buf, "ABC", 3) == 0);
    sz = wsocksend(s, "DEF", 3, -1);
    assert(errno == 0);
    assert(sz == 3);
    wsockdone(s, -1);
    assert(errno == 0);
    wsockclose(s);
}

int main() {
    wsock ls = wsocklisten(iplocal("127.0.0.1", 5555, 0), "sp3,sp2", 10);
    assert(ls);
    go(client());
    wsock s = wsockaccept(ls, -1);
    assert(s);
    assert(strcmp(wsockurl(s), "/a/b/c") == 0);
    assert(strcmp(wsocksubprotocol(s), "sp2") == 0);
    size_t sz = wsocksend(s, "ABC", 3, -1);
    assert(errno == 0);
    assert(sz == 3);
    char buf[3];
    sz = wsockrecv(s, buf, sizeof(buf), -1);
    assert(errno == 0);
    assert(sz == 3);
    assert(memcmp(buf, "DEF", 3) == 0);
    sz = wsockrecv(s, buf, sizeof(buf), -1);
    assert(errno == ECONNRESET);
    wsockclose(s);
    wsockclose(ls);
    return 0;
}
