/*
    Copyright (c) 2012-2013 Martin Sustrik  All rights reserved.
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

#ifndef WSOCK_WIRE_INCLUDED
#define WSOCK_WIRE_INCLUDED

#include <stdint.h>

uint16_t wsock_gets (const uint8_t *buf);
void wsock_puts (uint8_t *buf, uint16_t val);
uint32_t wsock_getl (const uint8_t *buf);
void wsock_putl (uint8_t *buf, uint32_t val);
uint64_t wsock_getll (const uint8_t *buf);
void wsock_putll (uint8_t *buf, uint64_t val);

#endif
