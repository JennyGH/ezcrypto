#ifndef _EZCRYPTO_H_
#define _EZCRYPTO_H_
#ifdef __cplusplus
#    include <vector>
#    include <string>
#    include <stdint.h>
#    define EZCRYPTO_NS ezcrypto
#    define EZCRYPTO_NS_BEGIN                                                                                          \
        namespace EZCRYPTO_NS                                                                                          \
        {
#    define EZCRYPTO_NS_END }
EZCRYPTO_NS_BEGIN
using byte_t    = uint8_t;
using word_t    = uint32_t;
using bytes_t   = std::vector<byte_t>;
using words_t   = std::vector<word_t>;
using mode_t    = enum class mode_t { ECB };
using padding_t = enum class padding_t { ZERO, PKCS7 };
class sm4;
EZCRYPTO_NS_END
#endif // __cplusplus
#endif // !_EZCRYPTO_H_