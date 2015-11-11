
#include <assert.h>
#include <libmill.h>

#include "../wsock.h"

coroutine void client() {
    ipaddr addr = ipremote("localhost", 5555, 0, -1);
    wsock s = wsockconnect(addr, "/a/b/c", -1);
    assert(s);
    wsockclose(s);
}

int main() {
    wsock ls = wsocklisten(iplocal("127.0.0.1", 5555, 0), 10);
    assert(ls);
    go(client());
    wsock s = wsockaccept(ls, -1);
    assert(s);
    wsockclose(s);
    wsockclose(ls);
    return 0;
}
