#ifndef _EZCRYPTO_SYMMETRIC_CIPHER_H_
#define _EZCRYPTO_SYMMETRIC_CIPHER_H_
#include "ezcrypto.h"
#ifdef __cplusplus
EZCRYPTO_NS_BEGIN
class abstract_symmetric_cipher
{
public:
    using final_callback_t = size_t (*)(void*, const void*, const size_t&);

public:
    abstract_symmetric_cipher()                                                        = default;
    ~abstract_symmetric_cipher()                                                       = default;
    virtual abstract_symmetric_cipher& update(const void* data, const size_t& length)  = 0;
    virtual size_t                     final(final_callback_t callback, void* context) = 0;
};
EZCRYPTO_NS_END
#endif // __cplusplus
#endif // !_EZCRYPTO_SYMMETRIC_CIPHER_H_