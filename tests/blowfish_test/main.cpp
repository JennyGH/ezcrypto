#include <chrono>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
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
    static const ezcrypto::byte_t expect_cipher[] =
        {0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78, 0xb0, 0xd4, 0xac, 0xb2, 0x8a, 0xa5, 0xeb, 0xe3};
    static const ezcrypto::padding_t padding = ezcrypto::padding_t::PKCS7;

    ezcrypto::bytes_t cipher;
    {
        ezcrypto::blowfish::ecb(true, padding, key, sizeof(key))
            .update(clear, sizeof(clear))
            .final(_final_callback, &cipher);
    }
    const bool is_cipher_correct =
        sizeof(expect_cipher) == cipher.size() && ::memcmp(expect_cipher, cipher.data(), cipher.size()) == 0;

    ezcrypto::bytes_t result;
    {
        ezcrypto::blowfish::ecb(false, padding, key, sizeof(key))
            .update(cipher.data(), cipher.size())
            .final(_final_callback, &result);
    }

    const bool is_clear_correct = sizeof(clear) == result.size() && ::memcmp(clear, result.data(), result.size()) == 0;

    return 0;
}