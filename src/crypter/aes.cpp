#include <crc32c/crc32c.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ciftl/crypter/aes.h>
#include <ciftl/crypter/core_crypter.h>

namespace ciftl
{
    AES128OFBCipherAlgorithm::AES128OFBCipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                       const byte *key_data, size_t key_len)
        : OriginalOpenSSLAES128CipherAlgorithm(
            OriginalOpenSSLAES128CipherAlgorithm::create_openssl_context(
                EVP_aes_128_ofb(), iv_data, iv_len, key_data, key_len))
    {
    }
}

namespace ciftl
{
    AES192OFBCipherAlgorithm::AES192OFBCipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                       const byte *key_data, size_t key_len)
        : OriginalOpenSSLAES192CipherAlgorithm(
            OriginalOpenSSLAES192CipherAlgorithm::create_openssl_context(
                EVP_aes_192_ofb(), iv_data, iv_len, key_data, key_len))
    {
    }
}

namespace ciftl
{
    AES256OFBCipherAlgorithm::AES256OFBCipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                       const byte *key_data, size_t key_len)
        : OriginalOpenSSLAES256CipherAlgorithm(
            OriginalOpenSSLAES256CipherAlgorithm::create_openssl_context(
                EVP_aes_256_ofb(), iv_data, iv_len, key_data, key_len))
    {
    }
}
