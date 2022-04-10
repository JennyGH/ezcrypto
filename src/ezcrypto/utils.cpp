#include "pch.h"
#include "utils.h"

using namespace EZCRYPTO_NS;

void zero_padding(bytes_t& bytes, const size_t& align)
{
    const size_t& length = bytes.length();
    if (length == 0)
    {
        return;
    }
    const size_t& remain = align - (length % align);
    if (remain == 0)
    {
        return;
    }
    bytes.append(remain, 0x00);
}

void pkcs7_padding(bytes_t& bytes, const size_t& align)
{
    const size_t& length = bytes.length();
    if (length == 0)
    {
        return;
    }
    const size_t& remain = align - (length % align);
    if (remain == 0)
    {
        return;
    }
    bytes.append(remain, remain);
}
