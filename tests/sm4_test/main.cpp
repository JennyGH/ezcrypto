#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ezcrypto.h>
#include <sm4.h>

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
    static const ezcrypto::byte_t cipher[] =
        {0x56, 0x8f, 0xe6, 0x67, 0xfa, 0xd9, 0x24, 0x31, 0xac, 0xf9, 0x5b, 0xe0, 0xe3, 0x5e, 0xed, 0xd5};
    static const ezcrypto::padding_t padding = ezcrypto::padding_t::PKCS7;

    ezcrypto::bytes_t encrypted;
    ezcrypto::sm4::ecb(true, padding, key).update(clear).final(_final_callback, &encrypted);
    if (sizeof(cipher) != encrypted.size())
    {
        return -1;
    }
    if (::memcmp(cipher, encrypted.data(), encrypted.size()) != 0)
    {
        return -1;
    }

    ezcrypto::bytes_t decrypted;
    ezcrypto::sm4::ecb(false, padding, key).update(cipher).final(_final_callback, &decrypted);
    if (sizeof(clear) != decrypted.size())
    {
        return -1;
    }
    if (::memcmp(clear, decrypted.data(), decrypted.size()) != 0)
    {
        return -1;
    }

    return 0;
}