#ifndef _PCH_H_
#define _PCH_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>

#ifdef SUPPORT_NOTHROW_NEW
#    define SAFE_NEW    new (std::nothrow)
#    define SAFE_DELETE delete
#else
#    define SAFE_NEW    new
#    define SAFE_DELETE delete
#endif // SUPPORT_NOTHROW_NEW

#define EZMIN(a, b) (a) < (b) ? (a) : (b)
#define EZMAX(a, b) (a) > (b) ? (a) : (b)
#define SHL(x, n)   (((x)&0xffffffff) << (n))
#define ROTL(x, n)  (SHL(x, n) | (x) >> (32 - (n)))

#endif // !_PCH_H_