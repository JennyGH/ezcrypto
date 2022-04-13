#include "pch.h"
#include "sm4.h"
#include "utils.h"

#define HEX(obj)  _hex_encode(obj)
#define CHEX(obj) _hex_encode(obj).c_str()

using namespace EZCRYPTO_NS;

static const word_t FK[] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};

static const word_t CK[] = {0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd,
                            0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81,
                            0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45,
                            0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279};

static const byte_t SBOX[] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a,
    0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef,
    0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80,
    0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19,
    0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d,
    0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00,
    0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40,
    0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
    0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23,
    0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c,
    0x5b, 0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a,
    0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d,
    0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48};

const size_t sm4::block_size = 16;

static inline std::string _hex_encode(byte_t e)
{
    std::string hex;
    char        buffer[3] = {0};
    ::sprintf_s(buffer, "%02x", e);
    hex.append(buffer, 2);
    return hex;
}

static inline std::string _hex_encode(word_t w)
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

static inline const byte_t& _SBox(const byte_t& a)
{
    return SBOX[(a >> 4 & 0x0f) * 0x10 + (a & 0x0f)];
}

// B = (b0, b1, b2, b3) = T(A) = (SBox(a0), SBox(a1), SBox(a2), SBox(a3))
static inline word_t _tau(const word_t& A)
{
    const byte_t& b0 = _SBox(byte_t((A & 0xff000000) >> 24));
    const byte_t& b1 = _SBox(byte_t((A & 0x00ff0000) >> 16));
    const byte_t& b2 = _SBox(byte_t((A & 0x0000ff00) >> 8));
    const byte_t& b3 = _SBox(byte_t((A & 0x000000ff) >> 0));
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | (b3);
}

// B' = L(B) = B ^ (B <<< 2) ^ (B <<< 10) ^ (B <<< 18) ^ (B <<< 24)
static inline word_t _L(const word_t& B)
{
    return B ^ ROTL(B, 2) ^ ROTL(B, 10) ^ ROTL(B, 18) ^ ROTL(B, 24);
}

// C = T(A) = L(tau(A))
static inline word_t _T(const word_t& A)
{
    return _L(_tau(A));
}

// B' = L'(B) = B ^ (B <<< 13) ^ (B <<< 23)
static inline word_t _L1(const word_t& B)
{
    return B ^ ROTL(B, 13) ^ ROTL(B, 23);
}

// C' = T'(A) = L'(tau(A))
static inline word_t _T1(const word_t& A)
{
    return _L1(_tau(A));
}

// F(Xi, Xi+1, Xi+2, Xi+3, rki) = Xi ^ T((Xi+1) ^ (Xi+2) ^ (Xi+3) ^ rki)
static inline word_t _F(const word_t& Xi, const word_t& Xi_1, const word_t& Xi_2, const word_t& Xi_3, const word_t& rki)
{
    return Xi ^ _T(Xi_1 ^ Xi_2 ^ Xi_3 ^ rki);
}

static inline words_t _rks_generator(const word_t& K0, const word_t& K1, const word_t& K2, const word_t& K3)
{
    word_t  K[] = {K0, K1, K2, K3};
    words_t rks;
    rks.resize(32);
    for (size_t i = 0; i < 32; i++)
    {
        const word_t rk = K[0] ^ _T1(K[1] ^ K[2] ^ K[3] ^ CK[i]);
        K[0]            = K[1];
        K[1]            = K[2];
        K[2]            = K[3];
        K[3]            = rk;
        rks[i]          = rk;
    }
    return rks;
}

static inline words_t _rks_generator(const words_t& K)
{
    if (K.size() != 4)
    {
        return words_t();
    }
    return _rks_generator(K[0], K[1], K[2], K[3]);
}

static inline bytes_t _make_zero_padding(const bytes_t& bytes, const size_t& block_size)
{
    bytes_t       padding;
    const size_t& length = bytes.size();
    const size_t& remain = block_size - (length % block_size);
    if (remain > 0)
    {
        padding.assign(remain, 0x00);
    }
    return padding;
}

static inline bytes_t _make_pkcs7_padding(const bytes_t& bytes, const size_t& block_size)
{
    bytes_t       padding;
    const size_t& length = bytes.size();
    const size_t& remain = block_size - (length % block_size);
    if (remain > 0)
    {
        padding.assign(remain, remain);
    }
    return padding;
}

static inline size_t _detect_padding_size(const bytes_t& bytes, const padding_t& padding_mode)
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
            for (size_t i = bytes_size - 1; i > 0; i--)
            {
                if (bytes[i] != 0x00)
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
            if (end > bytes_size)
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

template <typename T>
static inline T _bytes_to(const byte_t* bytes, const size_t& length, bool& success)
{
    if (nullptr == bytes || length < sizeof(T))
    {
        success = false;
        return (T)0;
    }

    T t = 0;

    success = sizeof(t) == safe_memcpy(bytes, sizeof(T), &t, sizeof(T));
    return to_bigendian(t);
}

static inline word_t _bytes_to_word(const byte_t* bytes, const size_t& length, bool& success)
{
    return _bytes_to<word_t>(bytes, length, success);
}

template <typename container_type>
static inline word_t _bytes_to_word(const container_type& bytes, bool& success)
{
    return _bytes_to<word_t>((const byte_t*)bytes.data(), bytes.size(), success);
}

static inline words_t _bytes_to_words(const byte_t* bytes, const size_t& length, bool& success)
{
    words_t      words;
    const size_t word_count = length / sizeof(word_t);
    words.resize(word_count);
    for (size_t i = 0; i < word_count; i++)
    {
        words[i] = _bytes_to<word_t>(bytes + i * sizeof(word_t), length - i * sizeof(word_t), success);
        if (!success)
        {
            words.clear();
            break;
        }
    }
    return words;
}

static inline words_t _init_key(const byte_t* MK, const size_t& MK_length)
{
    if (nullptr == MK || MK_length != 16)
    {
        return words_t();
    }
    const size_t rounds = MK_length / sizeof(word_t);
    words_t      words;
    words.resize(rounds);
    for (size_t i = 0; i < rounds; i++)
    {
        bool         success = false;
        const word_t w       = _bytes_to_word(MK + i * sizeof(word_t), MK_length - i * sizeof(word_t), success) ^ FK[i];
        if (!success)
        {
            // Bad convertion.
            words.clear();
            break;
        }
        words[i] = w;
    }
    return words;
}

class EZCRYPTO_NS::sm4_private
{
public:
    sm4_private()
        : _encrypt(false)
        , _mode(mode_t::ECB)
        , _padding(padding_t::PKCS7)
    {
    }

    sm4_private(const sm4_private& that)
        : _encrypt(that._encrypt)
        , _mode(that._mode)
        , _padding(that._padding)
        , _key(that._key)
        , _iv(that._iv)
        , _rks(that._rks)
        , _remain(that._remain)
    {
    }

    ~sm4_private() {}

public:
    bool      _encrypt;
    mode_t    _mode;
    padding_t _padding;
    words_t   _key;
    words_t   _iv;
    words_t   _rks;
    bytes_t   _output;
    bytes_t   _remain;
};

sm4::sm4(
    bool             encrypt,
    const mode_t&    mode,
    const padding_t& padding,
    const byte_t*    key,
    const size_t&    key_length,
    const byte_t*    iv,
    const size_t&    iv_length)
    : _data(SAFE_NEW sm4_private())
{
    if (nullptr != _data)
    {
        _data->_mode    = mode;
        _data->_encrypt = encrypt;
        if (nullptr != key && key_length > 0)
        {
            _data->_key = _init_key(key, key_length);
            _data->_rks = _rks_generator(_data->_key);
        }
        if (nullptr != iv && iv_length > 0)
        {
            bool success = false;
            _data->_iv   = _bytes_to_words(iv, iv_length, success);
        }
        _data->_padding = padding;
    }
}

sm4::sm4(const sm4& that)
    : _data(SAFE_NEW sm4_private())
{
    if (nullptr != that._data && nullptr != _data)
    {
        *_data = *that._data;
    }
}

sm4::sm4(sm4&& that) noexcept
    : _data(nullptr)
{
    std::swap(_data, that._data);
}

sm4::~sm4()
{
    if (nullptr != _data)
    {
        SAFE_DELETE _data;
        _data = nullptr;
    }
}

sm4& sm4::operator=(const sm4& that)
{
    if (&that != this)
    {
        if (nullptr != that._data && nullptr != _data)
        {
            *_data = *that._data;
        }
    }
    return *this;
}

sm4& sm4::operator=(sm4&& that) noexcept
{
    if (&that != this && _data != that._data)
    {
        std::swap(_data, that._data);
    }
    return *this;
}

sm4& sm4::update(const void* data, const size_t& length)
{
    if (nullptr != data && length > 0 && nullptr != _data)
    {
        const size_t  remain_size = _data->_remain.size();
        const size_t  total       = remain_size + length;
        const size_t  blocks      = total / sm4::block_size;
        const byte_t* bytes       = static_cast<const byte_t*>(data);

        if (total < sm4::block_size)
        {
            append_to_container(data, length, _data->_remain);
            return *this;
        }

        byte_t remain_blocks[sm4::block_size] = {0};
        {
            safe_memcpy(_data->_remain.data(), remain_size, remain_blocks, sizeof(remain_blocks));
            safe_memcpy(
                data,
                sm4::block_size - remain_size,
                remain_blocks + remain_size,
                sm4::block_size - remain_size);
        }

        const byte_t* current = remain_blocks;

        bool success = false;
        for (size_t i = 0; i < blocks; i++)
        {
            word_t X[4] = {0};

            for (size_t i = 0; i < 4; i++)
            {
                X[i] = _bytes_to_word(current + sizeof(word_t) * i, sizeof(word_t), success);
                if (!success)
                {
                    return *this;
                }
            }

            for (size_t i = 0; i < 32; i++)
            {
                const word_t& rki = _data->_rks[_data->_encrypt ? i : (31 - i)];
                const word_t  Xi  = _F(X[0], X[1], X[2], X[3], rki);
                X[0]              = X[1];
                X[1]              = X[2];
                X[2]              = X[3];
                X[3]              = Xi;
            }

            X[0] = to_bigendian(X[0]);
            X[1] = to_bigendian(X[1]);
            X[2] = to_bigendian(X[2]);
            X[3] = to_bigendian(X[3]);

            std::swap(X[3], X[0]);
            std::swap(X[2], X[1]);

            append_to_container(X, sizeof(X), _data->_output);

            if (i == 0)
            {
                current = bytes + sm4::block_size - remain_size;
            }
            else
            {
                current += sm4::block_size;
            }
        }

        const size_t remain_bytes = total % sm4::block_size;
        if (remain_bytes > 0)
        {
            _data->_remain.assign(bytes + length - remain_bytes, bytes + length);
        }
        else
        {
            _data->_remain.clear();
        }
    }
    return *this;
}

size_t sm4::final(final_callback_t callback, void* context)
{
    if (nullptr == _data)
    {
        return 0;
    }

    size_t output_size = 0;
    if (_data->_encrypt)
    {
        if (!_data->_remain.empty() || !_data->_output.empty())
        {
            switch (_data->_padding)
            {
                case padding_t::ZERO:
                {
                    update(_make_zero_padding(_data->_remain, sm4::block_size));
                    break;
                }
                case padding_t::PKCS7:
                {
                    update(_make_pkcs7_padding(_data->_remain, sm4::block_size));
                    break;
                }
                default:
                    break;
            }
        }
        output_size = _data->_output.size();
    }
    else
    {
        const size_t padding_size = _detect_padding_size(_data->_output, _data->_padding);
        output_size               = _data->_output.size() - padding_size;
    }

    if (nullptr != callback && output_size > 0)
    {
        output_size = callback(context, _data->_output.data(), output_size);
    }

    _data->_output.clear();
    _data->_remain.clear();

    return output_size;
}

sm4 sm4::ecb(bool encrypt, const padding_t& padding, const byte_t* key, const size_t& key_length)
{
    return sm4(encrypt, mode_t::ECB, padding, key, key_length, nullptr, 0);
}
