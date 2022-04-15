#include <benchmark/benchmark.h>
#include <ezcrypto/blowfish.h>
#include <string>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _MSC_VER
#    include <Windows.h>
#    define snprintf _snprintf
#else
#    include <unistd.h>
#endif // _MSC_VER

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

static inline void blowfish_test(bool encrypt, benchmark::State& state)
{
    static const ezcrypto::byte_t    key[16]  = {0x00};
    static const ezcrypto::byte_t    in[8192] = {0x00};
    static const ezcrypto::padding_t padding  = ezcrypto::padding_t::NONE;

    auto   cryptor = ezcrypto::blowfish::ecb(encrypt, padding, key);
    size_t bytes   = 0;
    size_t items   = 0;
    for (auto _ : state)
    {
        ezcrypto::bytes_t out;
        bytes += cryptor.update(in, sizeof(in)).final(_final_callback, &out);
        items++;
    }
    state.SetBytesProcessed(bytes);
    state.SetItemsProcessed(items);
}

static inline void blowfish_encrypt(benchmark::State& state)
{
    blowfish_test(true, state);
}

static inline void blowfish_decrypt(benchmark::State& state)
{
    blowfish_test(false, state);
}

BENCHMARK(blowfish_encrypt)->Unit(benchmark::kMicrosecond);
BENCHMARK(blowfish_decrypt)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();