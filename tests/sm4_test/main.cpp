#include <stdio.h>
#include <stdlib.h>
#include <ezcrypto.h>
#include <sm4.h>

static inline std::string _hex_encode(ezcrypto::byte_t e)
{
    std::string hex;
    char        buffer[3] = {0};
    ::sprintf_s(buffer, "%02x", e);
    hex.append(buffer, 2);
    return hex;
}

static inline std::string _hex_encode(ezcrypto::word_t w)
{
    std::string hex;
    char        buffer[9] = {0};
    ::sprintf_s(buffer, "%08x", w);
    hex.append(buffer, 8);
    return hex;
}

template <typename container_type>
static inline std::string _hex_encode(const container_type& src)
{
    std::string hex;
    for (const auto& e : src)
    {
        hex.append(_hex_encode(e));
    }
    return hex;
}

static inline size_t _final_callback(void* context, const void* data, const size_t& length)
{
    const ezcrypto::byte_t* bytes  = static_cast<const ezcrypto::byte_t*>(data);
    ezcrypto::bytes_t*      buffer = static_cast<ezcrypto::bytes_t*>(context);
    if (nullptr == buffer)
    {
        return 0;
    }
    buffer->assign(bytes, bytes + length);
    return length;
}

int main(int argc, char** argv)
{
    static const ezcrypto::byte_t key[16] = {0x00};
    static const ezcrypto::byte_t clear[] =
        {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    static const ezcrypto::padding_t padding = ezcrypto::padding_t::PKCS7;

    ezcrypto::bytes_t cipher;
    {
        ezcrypto::sm4::ecb(true, padding, key, sizeof(key))
            .update(clear, sizeof(clear))
            .final(_final_callback, &cipher);
    }

    ezcrypto::bytes_t result;
    {
        ezcrypto::sm4::ecb(false, padding, key, sizeof(key))
            .update(cipher.data(), cipher.size())
            .final(_final_callback, &result);
    }

    const bool correct = sizeof(clear) == result.size() && ::memcmp(clear, result.data(), result.size()) == 0;

    return 0;
}