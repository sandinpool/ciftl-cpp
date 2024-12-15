#pragma once
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <ciftl/crypter/crypter.h>
#include <ciftl/etc/etc.h>


namespace ciftl
{
    constexpr static size_t SM4_KEY_LENGTH = 16;
    constexpr static size_t SM4_IV_LENGTH = 16;
    constexpr static size_t SM4_BLOCK_LENGTH = 16;

    typedef OpenSSLCipherAlgorithm<SM4_IV_LENGTH, SM4_KEY_LENGTH, SM4_BLOCK_LENGTH>
    OriginalOpenSSLSM4CipherAlgorithm;

    class OpenSSLSM4OFBCipherAlgorithm : public OriginalOpenSSLSM4CipherAlgorithm
    {
    public:
        OpenSSLSM4OFBCipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);

        ~OpenSSLSM4OFBCipherAlgorithm() = default;
    };
}
