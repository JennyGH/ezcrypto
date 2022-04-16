#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <iostream>
#include <ezcrypto.h>
#include <blowfish.h>

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
    static const ezcrypto::byte_t key[16]  = {0x00};
    static const ezcrypto::byte_t clear[8] = {0x00};
    static const ezcrypto::byte_t cipher[] =
        {0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78, 0xb0, 0xd4, 0xac, 0xb2, 0x8a, 0xa5, 0xeb, 0xe3};
    static const ezcrypto::padding_t padding = ezcrypto::padding_t::PKCS7;

    ezcrypto::bytes_t encrypted;
    ezcrypto::blowfish::ecb(true, padding, key).update(clear).final(_final_callback, &encrypted);
    if (sizeof(cipher) != encrypted.size())
    {
        return -1;
    }
    if (::memcmp(cipher, encrypted.data(), encrypted.size()) != 0)
    {
        return -1;
    }

    ezcrypto::bytes_t decrypted;
    ezcrypto::blowfish::ecb(false, padding, key).update(encrypted).final(_final_callback, &decrypted);
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