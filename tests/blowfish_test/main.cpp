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
    static const ezcrypto::byte_t key[16] = {0x00};
    static const ezcrypto::byte_t clear[16] =
        {0x30, 0x31, 0x32, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x31, 0x32, 0x33};
    static const ezcrypto::byte_t expect_cipher[16] =
        {0xdb, 0x73, 0xde, 0xa8, 0x9c, 0x51, 0xee, 0x23, 0xdb, 0x73, 0xde, 0xa8, 0x9c, 0x51, 0xee, 0x23};
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

    const bool correct = sizeof(clear) == result.size() && ::memcmp(clear, result.data(), result.size()) == 0;
    return 0;
}