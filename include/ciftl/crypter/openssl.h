#pragma once
#include <ciftl/etc/etc.h>
#include <ciftl/crypter/crypter.h>

namespace ciftl
{
    typedef std::unique_ptr<EVP_CIPHER_CTX, std::function<void(EVP_CIPHER_CTX *)> > EVP_CIPHER_CTX_UniquePtr;

    // OpenSSL加密密码流生成器
    template<size_t M_IV_LENGTH, size_t M_KEY_LENGTH, size_t M_BLOCK_LENGTH = 0>
    class OpenSSLCipherAlgorithm : public ICipherAlgorithm
    {
    public:
        static constexpr size_t IV_LENGTH = M_IV_LENGTH;
        static constexpr size_t KEY_LENGTH = M_KEY_LENGTH;
        static constexpr size_t BLOCK_LENGTH = M_BLOCK_LENGTH;

        static EVP_CIPHER_CTX_UniquePtr create_openssl_context(const EVP_CIPHER *evp_cipher,
                                                               const byte *iv_data, size_t iv_len,
                                                               const byte *key_data, size_t key_len)
        {
            assert(iv_len == IV_LENGTH);
            assert(key_len == KEY_LENGTH);
            int iv_length = EVP_CIPHER_iv_length(evp_cipher);
            int key_length = EVP_CIPHER_key_length(evp_cipher);
            assert(iv_len == iv_length);
            assert(key_len == key_length);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                throw std::bad_alloc();
            }
            // 初始化加密操作
            if (!EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key_data, iv_data)) {
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

    public:
        OpenSSLCipherAlgorithm(EVP_CIPHER_CTX_UniquePtr &&ctx)
            : m_ctx(std::move(ctx))
        {
        }

        ~OpenSSLCipherAlgorithm()
        {
        }

    public:
        Result<void> crypt(const byte *src_data, size_t src_len, byte *dst_data, size_t dst_len) noexcept override
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

        [[nodiscard]] size_t iv_length() const noexcept override { return IV_LENGTH; }
        [[nodiscard]] size_t key_length() const noexcept override { return KEY_LENGTH; }
        [[nodiscard]] size_t block_length() const noexcept override { return BLOCK_LENGTH; }

    protected:
        // OpenSSL上下文
        EVP_CIPHER_CTX_UniquePtr m_ctx;
    };
}
