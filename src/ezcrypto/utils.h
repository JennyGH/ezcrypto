#ifndef _EZCRYPTO_UTILS_H_
#define _EZCRYPTO_UTILS_H_
#include "ezcrypto.h"
#include "platform_compatibility.h"
EZCRYPTO_NS_BEGIN
size_t detect_padding_size(const bytes_t& bytes, const padding_t& padding_mode, const size_t& block_size);
bool   is_bigendian();
template <typename T>
inline typename std::enable_if<(sizeof(T) == 1), const T&>::type to_bigendian(const T& in)
{
    return in;
}
template <typename T>
inline typename std::enable_if<(sizeof(T) == 2), T>::type to_bigendian(const T& in)
{
    if (is_bigendian())
    {
        return in;
    }
    return ((in & 0x00FF) << 8) | ((in & 0xFF00) >> 8);
}
template <typename T>
inline typename std::enable_if<(sizeof(T) == 4), T>::type to_bigendian(const T& in)
{
    if (is_bigendian())
    {
        return in;
    }
    return ((in & 0x000000FF) << 24) | ((in & 0x0000FF00) << 8) | ((in & 0x00FF0000) >> 8) | ((in & 0xFF000000) >> 24);
}
template <typename T>
inline typename std::enable_if<(sizeof(T) == 8), T>::type to_bigendian(const T& in)
{
    if (is_bigendian())
    {
        return in;
    }
    return ((in & 0x00000000000000FF) << 56) | ((in & 0x000000000000FF00) << 40) | ((in & 0x0000000000FF0000) << 24) |
           ((in & 0x00000000FF000000) << 8) | ((in & 0x000000FF00000000) >> 8) | ((in & 0x0000FF0000000000) >> 24) |
           ((in & 0x00FF000000000000) >> 40) | ((in & 0xFF00000000000000) >> 56);
}
template <typename T>
inline typename std::enable_if<(sizeof(T) == 8), T>::type bytes_to(
    const uint8_t* bytes,
    const size_t&  length,
    bool&          success)
{
    if (nullptr == bytes || length < sizeof(T))
    {
        success = false;
        return (T)0;
    }
    success = true;
    T value = 0;
    value |= bytes[0];
    value <<= 8;
    value |= bytes[1];
    value <<= 8;
    value |= bytes[2];
    value <<= 8;
    value |= bytes[3];
    value <<= 8;
    value |= bytes[4];
    value <<= 8;
    value |= bytes[5];
    value <<= 8;
    value |= bytes[6];
    value <<= 8;
    value |= bytes[7];
    return value;
    // return (bytes[0] << 56) | (bytes[1] << 48) | (bytes[2] << 40) | (bytes[3] << 32) | (bytes[4] << 24) |
    //        (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
}

template <typename T>
inline typename std::enable_if<(sizeof(T) == 4), T>::type bytes_to(
    const uint8_t* bytes,
    const size_t&  length,
    bool&          success)
{
    if (nullptr == bytes || length < sizeof(T))
    {
        success = false;
        return (T)0;
    }
    success = true;
    T value = 0;
    value |= bytes[0];
    value <<= 8;
    value |= bytes[1];
    value <<= 8;
    value |= bytes[2];
    value <<= 8;
    value |= bytes[3];
    return value;
    // return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

template <typename T>
inline typename std::enable_if<(sizeof(T) == 2), T>::type bytes_to(
    const uint8_t* bytes,
    const size_t&  length,
    bool&          success)
{
    if (nullptr == bytes || length < sizeof(T))
    {
        success = false;
        return (T)0;
    }
    success = true;
    T value = 0;
    value |= bytes[0];
    value <<= 8;
    value |= bytes[1];
    return value;
    // return (bytes[0] << 8) | bytes[1];
}

template <typename T>
inline typename std::enable_if<(sizeof(T) == 1), const T&>::type bytes_to(
    const uint8_t* bytes,
    const size_t&  length,
    bool&          success)
{
    if (nullptr == bytes || length < sizeof(T))
    {
        success = false;
        return (T)0;
    }
    success = true;
    return bytes[0];
}

template <typename T, size_t L>
inline T bytes_to(const uint8_t (&bytes)[L])
{
    bool success = false;
    return bytes_to<T>(bytes, L, success);
}

template <size_t block_size>
inline size_t make_zero_padding(byte_t (&dst)[block_size], const size_t& dst_current_size)
{
    const size_t remain = block_size - (dst_current_size % block_size);
    if (remain > 0)
    {
        ::memset(dst + dst_current_size, 0x00, remain);
    }
    return remain;
}

template <size_t block_size>
inline size_t make_pkcs7_padding(byte_t (&dst)[block_size], const size_t& dst_current_size)
{
    const size_t remain = block_size - (dst_current_size % block_size);
    if (remain > 0)
    {
        ::memset(dst + dst_current_size, remain & 0xFF, remain);
    }
    return remain;
}

template <size_t block_size>
inline size_t make_padding(const padding_t& padding, byte_t (&dst)[block_size], const size_t& dst_current_size)
{
    switch (padding)
    {
        case padding_t::ZERO:
            return make_zero_padding(dst, dst_current_size);
        case padding_t::PKCS7:
            return make_pkcs7_padding(dst, dst_current_size);
        default:
            break;
    }
    return 0;
}

EZCRYPTO_NS_END
#endif // !_EZCRYPTO_UTILS_H_