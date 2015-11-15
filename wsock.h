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

#ifndef WSOCK_H_INCLUDED
#define WSOCK_H_INCLUDED

#include <libmill.h>

/******************************************************************************/
/*  ABI versioning support                                                    */
/******************************************************************************/

/*  Don't change this unless you know exactly what you're doing and have      */
/*  read and understand the following documents:                              */
/*  www.gnu.org/software/libtool/manual/html_node/Libtool-versioning.html     */
/*  www.gnu.org/software/libtool/manual/html_node/Updating-version-info.html  */

/*  The current interface version. */
#define WSOCK_VERSION_CURRENT 0

/*  The latest revision of the current interface. */
#define WSOCK_VERSION_REVISION 0

/*  How many past interface versions are still supported. */
#define WSOCK_VERSION_AGE 0

/******************************************************************************/
/*  Symbol visibility                                                         */
/******************************************************************************/

#if defined WSOCK_NO_EXPORTS
#   define WSOCK_EXPORT
#else
#   if defined _WIN32
#      if defined WSOCK_EXPORTS
#          define WSOCK_EXPORT __declspec(dllexport)
#      else
#          define WSOCK_EXPORT __declspec(dllimport)
#      endif
#   else
#      if defined __SUNPRO_C
#          define WSOCK_EXPORT __global
#      elif (defined __GNUC__ && __GNUC__ >= 4) || \
             defined __INTEL_COMPILER || defined __clang__
#          define WSOCK_EXPORT __attribute__ ((visibility("default")))
#      else
#          define WSOCK_EXPORT
#      endif
#   endif
#endif

/******************************************************************************/
/*  wsock library                                                             */
/******************************************************************************/

typedef struct wsock *wsock;

WSOCK_EXPORT wsock wsocklisten(ipaddr addr, const char *subprotocol,
    int backlog);
WSOCK_EXPORT wsock wsockaccept(wsock s, int64_t deadline);
WSOCK_EXPORT wsock wsockconnect(ipaddr addr, const char *subprotocol,
    const char *url, int64_t deadline);
WSOCK_EXPORT const char *wsockurl(wsock s);
WSOCK_EXPORT const char *wsocksubprotocol(wsock s);
WSOCK_EXPORT size_t wsocksend(wsock s, const void *msg, size_t len,
    int64_t deadline);
WSOCK_EXPORT size_t wsockrecv(wsock s, void *msg, size_t len,
    int64_t deadline); 
WSOCK_EXPORT void wsockclose(wsock s);

#endif

