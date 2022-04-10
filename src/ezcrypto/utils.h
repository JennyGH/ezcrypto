#ifndef _EZCRYPTO_UTILS_H_
#define _EZCRYPTO_UTILS_H_
#include "ezcrypto.h"
EZCRYPTO_NS_BEGIN
void zero_padding(bytes_t& bytes, const size_t& align);
void pkcs7_padding(bytes_t& bytes, const size_t& align);
EZCRYPTO_NS_END
#endif // !_EZCRYPTO_UTILS_H_