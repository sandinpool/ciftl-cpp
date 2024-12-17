#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ciftl/crypter/crypter.h>
#include <ciftl/etc/etc.h>

namespace ciftl
{
    inline EVP_CIPHER_CTX_UniquePtr create_openssl_context(const byte *iv_data, size_t iv_len,
                                                           const byte *key_data, size_t key_len)
    {
        assert(iv_len == CHACHA20_IV_LENGTH);
        assert(key_len == CHACHA20_KEY_LENGTH);
        const EVP_CIPHER *evp = EVP_chacha20();
        int iv_length = EVP_CIPHER_iv_length(evp);
        int key_length = EVP_CIPHER_key_length(evp);
        // 这里比较特殊，因为openssl的chacha20的iv长度为16字节，前4个字节需要置0，所以这里长度判断需要加4
        assert(iv_len + 4 == iv_length);
        assert(key_len == key_length);
        auto filled_iv_data = std::make_unique<unsigned char[]>(iv_length);
        // 忽略前4个字节，只填充后12个字节
        memcpy(filled_iv_data.get() + 4, iv_data, CHACHA20_IV_LENGTH);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::bad_alloc();
        }
        // 初始化加密操作
        if (!EVP_EncryptInit_ex(ctx, evp, NULL, key_data, filled_iv_data.get())) {
            throw std::bad_alloc();
        }
        std::unique_ptr<EVP_CIPHER_CTX, std::function<void(EVP_CIPHER_CTX *)> > ctx_ptr(ctx, [](EVP_CIPHER_CTX *ctx)
        {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
        });
        return ctx_ptr;
    }

    ChaCha20CipherAlgorithm::ChaCha20CipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                     const byte *key_data, size_t key_len)
        : m_ctx(create_openssl_context(iv_data, iv_len, key_data, key_len))
    {
    }

    Result<void> ChaCha20CipherAlgorithm::crypt(const byte *src_data, size_t src_len,
                                                byte *dst_data, size_t dst_len) noexcept
    {
        if (src_len != dst_len) {
            return Result<void>::make_err(SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH);
        }
        // 执行加密，这里是对m_plaintext_buffer进行加密，并将结果拷贝到temp_buffer中
        int out_len;
        if (!EVP_EncryptUpdate(m_ctx.get(), dst_data, &out_len, src_data, (int) src_len)) {
            return Result<void>::make_err(FAILED_WHEN_EVP_ENCRYPT_UPDATE);
        }
        // 传入长度应该和输出长度一致
        if (out_len != dst_len) {
            return Result<void>::make_err(FAILED_WHEN_EVP_ENCRYPT_UPDATE);
        }
        return Result<void>::make_ok();
    }
}
