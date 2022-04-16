#include "pch.h"
#include "utils.h"

using namespace EZCRYPTO_NS;

bool EZCRYPTO_NS::is_bigendian()
{
    static const uint16_t data  = 0x1234;
    static const bool     value = reinterpret_cast<const uint8_t*>(&data)[0] == 0x12;
    return value;
}

size_t EZCRYPTO_NS::detect_padding_size(const bytes_t& bytes, const padding_t& padding_mode, const size_t& block_size)
{
    const size_t bytes_size = bytes.size();
    size_t       size       = 0;
    if (bytes.empty())
    {
        return size;
    }
    switch (padding_mode)
    {
        case padding_t::ZERO:
        {
            for (size_t i = 0; i < block_size; i++)
            {
                if (bytes[bytes_size - 1 - i] != 0x00)
                {
                    break;
                }
                size++;
            }
            break;
        }
        case padding_t::PKCS7:
        {
            const byte_t end = bytes[bytes_size - 1];
            if (end > block_size)
            {
                return size;
            }
            byte_t last = bytes[bytes_size - end];
            for (size_t i = bytes_size - end; i < bytes_size; i++)
            {
                if (bytes[i] != last)
                {
                    break;
                }
                size++;
            }
            break;
        }
        default:
            break;
    }
    return size;
}