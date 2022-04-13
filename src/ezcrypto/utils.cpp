#include "pch.h"
#include "utils.h"

using namespace EZCRYPTO_NS;

size_t EZCRYPTO_NS::safe_memcpy(const void* src, const size_t& src_size, void* dst, const size_t& dst_size)
{
    if (nullptr == dst || 0 == dst_size)
    {
        return 0;
    }
    errno_t err = ::memcpy_s(dst, dst_size, src, src_size);
    if (0 == err)
    {
        return src_size;
    }
    return 0;
}

bool EZCRYPTO_NS::is_bigendian()
{
    static const uint16_t data  = 0x1234;
    static const bool     value = reinterpret_cast<const uint8_t*>(&data)[0] == 0x12;
    return value;
}
