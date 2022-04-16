#ifndef _EZCRYPTO_BLOWFISH_H_
#define _EZCRYPTO_BLOWFISH_H_
#include "ezcrypto.h"
#include "symmetric_cipher.h"
#ifdef __cplusplus
EZCRYPTO_NS_BEGIN
class blowfish_private;
class blowfish : public abstract_symmetric_cipher
{
public:
    using final_callback_t = size_t (*)(void*, const void*, const size_t&);

public:
    blowfish(bool encrypt, const mode_t& mode, const padding_t& padding, const byte_t* key, const size_t& key_length);

    template <size_t key_length>
    inline blowfish(bool encrypt, const mode_t& mode, const padding_t& padding, const byte_t (&key)[key_length])
        : blowfish(encrypt, mode, padding, key, key_length)
    {
        // ...
    }

    blowfish(const blowfish& that);
    blowfish(blowfish&& that) noexcept;
    ~blowfish();
    blowfish& operator=(const blowfish& that);
    blowfish& operator=(blowfish&& that) noexcept;

    blowfish& update(const void* data, const size_t& length) override;

    template <size_t length>
    blowfish& update(const byte_t (&data)[length])
    {
        return update(data, length);
    }

    template <typename container_type>
    blowfish& update(const container_type& bytes)
    {
        return update(bytes.data(), bytes.size());
    }

    size_t final(final_callback_t callback, void* context) override;

public:
    static blowfish ecb(bool encrypt, const padding_t& padding, const byte_t* key, const size_t& key_length);
    template <size_t key_length>
    static inline blowfish ecb(bool encrypt, const padding_t& padding, const byte_t (&key)[key_length])
    {
        return blowfish::ecb(encrypt, padding, key, key_length);
    }

private:
    blowfish_private* _data;
};
EZCRYPTO_NS_END
#endif // __cplusplus
#endif // !_EZCRYPTO_BLOWFISH_H_