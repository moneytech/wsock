# wsock

wsock is WebSocket library for [libmill](http://libmill.org)

# Reference

**wsock wsocklisten(ipaddr addr, const char *subprotocol, int backlog);**

Start listening for connections from clients. Subprotocol is a comma-delimited
list of supported subprotocols. Incoming connections that don't match any of
the listed subprotocols will be silently dropped. If it is set to NULL, all
connections will be accepted.

**wsock wsockaccept(wsock s, int64_t deadline);**

Accept new connection from a client.

**wsock wsockconnect(ipaddr addr, const char *subprotocol, const char *url, int64_t deadline);**

Connect to a server. Subprotocol is a comma-delimited list of supported
subprotocols. Put preferred protocols before less preferred ones. Server will
choose one of the subprotocols -- to find out which one, use wsocksubprotocol()
function. Setting subprotocol to NULL means that the server is free to choose
any subprotocol.

**const char *wsockurl(wsock s);**

After accepting a connection, you can retrieve the URL requested by peer using
this function.

**const char *wsocksubprotocol(wsock s);**

Get subprotocol the socket is using. If you've specified multiple subprotocols
with wsocklisten() or wsockconnect(), this function lets you know which one
of them was chosen to be used.

**size_t wsocksend(wsock s, const void *msg, size_t len, int64_t deadline);**

Send a message to the peer.

**size_t wsockrecv(wsock s, void *msg, size_t len, int64_t deadline);**

Receive a message from the peer.

**void wsockping(wsock s, int64_t deadline);**

Send ping to the peer. Peer replies with pong, which will cause wsockrecv()
to exit with errno set to EAGAIN.

**void wsockpong(wsock s, int64_t deadline);**

Send pong to the peer. It can be used to implement unsolicited one-way
heartbeats.

**void wsockdone(wsock s, int64_t deadline);**

Start the closing handshake. After calling this function you can't send
any more messages, however, you can still receive pending messages from the
peer.

**void wsockclose(wsock s);**

Close the connection without doing the closing handshake.

