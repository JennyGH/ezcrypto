#ifndef _EZCRYPTO_SM4_H_
#define _EZCRYPTO_SM4_H_
#include "ezcrypto.h"
#include "symmetric_cipher.h"
#ifdef __cplusplus
EZCRYPTO_NS_BEGIN
class sm4_private;
class sm4 : public abstract_symmetric_cipher
{
public:
    sm4(bool             encrypt,
        const mode_t&    mode,
        const padding_t& padding,
        const byte_t*    key,
        const size_t&    key_length,
        const byte_t*    iv,
        const size_t&    iv_length);

    template <size_t key_length>
    sm4(bool             encrypt,
        const mode_t&    mode,
        const padding_t& padding,
        const byte_t (&key)[key_length],
        const byte_t* iv,
        const size_t& iv_length)
        : sm4(encrypt, mode, padding, key, key_length, iv, iv_length)
    {
        // ...
    }

    sm4(const sm4& that);
    sm4(sm4&& that) noexcept;
    ~sm4();
    sm4& operator=(const sm4& that);
    sm4& operator=(sm4&& that) noexcept;

    sm4& update(const void* data, const size_t& length) override;

    template <size_t length>
    sm4& update(const byte_t (&data)[length])
    {
        return update(data, length);
    }

    template <typename container_type>
    sm4& update(const container_type& bytes)
    {
        return update(bytes.data(), bytes.size());
    }

    size_t final(final_callback_t callback, void* context) override;

public:
    static sm4 ecb(bool encrypt, const padding_t& padding, const byte_t* key, const size_t& key_length);
    template <size_t key_length>
    static inline sm4 ecb(bool encrypt, const padding_t& padding, const byte_t (&key)[key_length])
    {
        return ecb(encrypt, padding, key, key_length);
    }

private:
    sm4_private* _data;
};
EZCRYPTO_NS_END
#endif // __cplusplus
#endif // !_EZCRYPTO_SM4_H_