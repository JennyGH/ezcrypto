#ifndef _EZCRYPTO_UTILS_H_
#define _EZCRYPTO_UTILS_H_
#include "ezcrypto.h"
EZCRYPTO_NS_BEGIN
size_t safe_memcpy(const void* src, const size_t& src_size, void* dst, const size_t& dst_size);
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

template <typename container_type, typename element_type>
inline container_type& append_to_container(const element_type* src, const size_t& size, container_type& dst)
{
    if (nullptr != src && size > 0)
    {
        const size_t offset = dst.size();
        dst.resize(offset + size);
        safe_memcpy(src, size, &dst[offset], size);
    }
    return dst;
}

template <typename T>
static inline typename std::enable_if<(sizeof(T) == 8), T>::type bytes_to(
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
    return (bytes[0] << 56) | (bytes[1] << 48) | (bytes[2] << 40) | (bytes[3] << 32) | (bytes[4] << 24) |
           (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
}

template <typename T>
static inline typename std::enable_if<(sizeof(T) == 4), T>::type bytes_to(
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
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

template <typename T>
static inline typename std::enable_if<(sizeof(T) == 2), T>::type bytes_to(
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
    return (bytes[0] << 8) | bytes[1];
}

template <typename T>
static inline typename std::enable_if<(sizeof(T) == 1), const T&>::type bytes_to(
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

EZCRYPTO_NS_END
#endif // !_EZCRYPTO_UTILS_H_