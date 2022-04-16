#ifndef _EZCRYPTO_SYMMETRIC_CIPHER_PRIVATE_H_
#define _EZCRYPTO_SYMMETRIC_CIPHER_PRIVATE_H_
#include "ezcrypto.h"
#include "symmetric_cipher.h"
#ifdef __cplusplus
EZCRYPTO_NS_BEGIN
template <size_t L>
class symmetric_cipher_private : public abstract_symmetric_cipher
{
public:
    using final_callback_t = size_t (*)(void*, const void*, const size_t&);

public:
    symmetric_cipher_private(bool encrypt, const padding_t& padding, const mode_t& mode)
        : _encrypt(encrypt)
        , _padding(padding)
        , _mode(mode)
        , _remain_size(0)
    {
        ::memset(_remain, 0, sizeof(_remain));
    }

    symmetric_cipher_private(const symmetric_cipher_private& that)
        : _encrypt(that._encrypt)
        , _padding(that._padding)
        , _mode(that._mode)
        , _remain_size(that._remain_size)
        , _output(that._output)
    {
        ::memcpy(_remain, that._remain, sizeof(that._remain_size));
    }

    ~symmetric_cipher_private() = default;

    symmetric_cipher_private& update(const void* data, const size_t& length) override
    {
        if (nullptr != data && length > 0)
        {
            const size_t& remain_size = _remain_size;
            const size_t  total       = remain_size + length;
            const size_t  blocks      = total / block_size;
            const byte_t* bytes       = static_cast<const byte_t*>(data);
            const byte_t* current     = bytes;

            if (total < block_size)
            {
                ::memcpy_s(_remain + remain_size, sizeof(_remain) - remain_size, data, length);
                _remain_size = total;
                return *this;
            }

            bool has_remain  = false;
            bool is_combined = false;
            if (remain_size > 0)
            {
                has_remain = true;
                if (remain_size < block_size)
                {
                    ::memcpy_s(_remain + remain_size, block_size - remain_size, data, block_size - remain_size);
                    is_combined = true;
                }
                current = _remain;
            }

            size_t offset = _output.size();
            _output.resize(offset + blocks * block_size);
            byte_t* output = &_output[offset];

            for (size_t i = 0; i < blocks; i++)
            {
                update_block(_encrypt, current, output);
                output += block_size;

                if (has_remain)
                {
                    if (is_combined)
                    {
                        current     = bytes + block_size - remain_size;
                        is_combined = false;
                    }
                    else
                    {
                        current = bytes;
                    }
                    has_remain = false;
                }
                else
                {
                    current += block_size;
                }
            }

            _remain_size = total % block_size;
            if (_remain_size > 0)
            {
                ::memcpy_s(_remain, sizeof(_remain) - _remain_size, bytes + length - _remain_size, _remain_size);
            }
        }
        return *this;
    }

    size_t final(final_callback_t callback, void* context) override
    {
        size_t output_size = 0;
        if (_encrypt)
        {
            if (_remain_size > 0 || !_output.empty())
            {
                const size_t padding_size = make_padding(_padding, _remain, _remain_size);
                if (padding_size > 0)
                {
                    update(_remain + _remain_size, padding_size);
                }
            }
            output_size = _output.size();
        }
        else
        {
            const size_t padding_size = detect_padding_size(_output, _padding, block_size);
            output_size               = _output.size() - padding_size;
        }

        if (nullptr != callback && output_size > 0)
        {
            output_size = callback(context, _output.data(), output_size);
        }

        _output.clear();
        _remain_size = 0;

        return output_size;
    }

    virtual void update_block(bool is_encrypt, const byte_t* in, byte_t* out) = 0;

public:
    static const size_t block_size;

private:
    bool      _encrypt;
    padding_t _padding;
    mode_t    _mode;
    byte_t    _remain[L];
    size_t    _remain_size;
    bytes_t   _output;
};
template <size_t L>
const size_t symmetric_cipher_private<L>::block_size = L;
EZCRYPTO_NS_END
#endif // __cplusplus
#endif // !_EZCRYPTO_SYMMETRIC_CIPHER_PRIVATE_H_