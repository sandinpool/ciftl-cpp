#include <crc32c/crc32c.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ciftl/crypter/sm4.h>
#include <ciftl/crypter/core_crypter.h>

namespace ciftl
{
    OpenSSLSM4OFBCipherAlgorithm::OpenSSLSM4OFBCipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                               const byte *key_data, size_t key_len)
        : OriginalOpenSSLSM4CipherAlgorithm(
            OriginalOpenSSLAES128CipherAlgorithm::create_openssl_context(
                EVP_sm4_ofb(), iv_data, iv_len, key_data, key_len))
    {
    }
}
