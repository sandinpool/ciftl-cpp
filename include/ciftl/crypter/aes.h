#pragma once
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ciftl/crypter/crypter.h>
#include <ciftl/etc/etc.h>

namespace ciftl
{
    constexpr static size_t AES128_KEY_LENGTH = 16;
    constexpr static size_t AES128_IV_LENGTH = 16;
    constexpr static size_t AES128_BLOCK_LENGTH = 16;

    typedef OpenSSLCipherAlgorithm<AES128_IV_LENGTH, AES128_KEY_LENGTH, AES128_BLOCK_LENGTH>
    OriginalOpenSSLAES128CipherAlgorithm;

    class OpenSSLAES128OFBCipherAlgorithm : public OriginalOpenSSLAES128CipherAlgorithm
    {
    public:
        OpenSSLAES128OFBCipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);

        ~OpenSSLAES128OFBCipherAlgorithm() = default;
    };
}

namespace ciftl
{
    constexpr static size_t AES192_KEY_LENGTH = 24;
    constexpr static size_t AES192_IV_LENGTH = 16;
    constexpr static size_t AES192_BLOCK_LENGTH = 16;

    typedef OpenSSLCipherAlgorithm<AES192_IV_LENGTH, AES192_KEY_LENGTH, AES192_BLOCK_LENGTH>
    OriginalOpenSSLAES192CipherAlgorithm;

    class OpenSSLAES192OFBCipherAlgorithm : public OriginalOpenSSLAES192CipherAlgorithm
    {
    public:
        OpenSSLAES192OFBCipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);

        ~OpenSSLAES192OFBCipherAlgorithm() = default;
    };
}

namespace ciftl
{
    constexpr static size_t AES256_KEY_LENGTH = 32;
    constexpr static size_t AES256_IV_LENGTH = 16;
    constexpr static size_t AES256_BLOCK_LENGTH = 16;

    typedef OpenSSLCipherAlgorithm<AES256_IV_LENGTH, AES256_KEY_LENGTH, AES256_BLOCK_LENGTH>
    OriginalOpenSSLAES256CipherAlgorithm;

    class OpenSSLAES256OFBCipherAlgorithm : public OriginalOpenSSLAES256CipherAlgorithm
    {
    public:
        OpenSSLAES256OFBCipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);

        ~OpenSSLAES256OFBCipherAlgorithm() = default;
    };
}
