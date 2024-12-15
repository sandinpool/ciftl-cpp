#pragma once
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <botan/stream_cipher.h>

#include <ciftl/crypter/crypter.h>
#include <ciftl/etc/etc.h>

#include "openssl.h"

namespace ciftl
{
    constexpr static size_t CHACHA20_KEY_LENGTH = 32;
    constexpr static size_t CHACHA20_IV_LENGTH = 12;
    constexpr static size_t CHACHA20_BLOCK_LENGTH = 0;

    /// ChaCha20算法
    class ChaCha20CipherAlgorithm final : public ICipherAlgorithm
    {
    public:
        static constexpr size_t IV_LENGTH = CHACHA20_IV_LENGTH;
        static constexpr size_t KEY_LENGTH = CHACHA20_KEY_LENGTH;
        static constexpr size_t BLOCK_LENGTH = CHACHA20_BLOCK_LENGTH;

    public:
        ChaCha20CipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);

    public:
        [[nodiscard]] Result<void>
        crypt(const byte *src_data, size_t src_len, byte *dst_data, size_t dst_len) noexcept override;

        [[nodiscard]] size_t iv_length() const noexcept override { return IV_LENGTH; }

        [[nodiscard]] size_t key_length() const noexcept override { return KEY_LENGTH; }

        [[nodiscard]] size_t block_length() const noexcept override { return BLOCK_LENGTH; }

    private:
        std::unique_ptr<Botan::StreamCipher> m_botan_chacha20;
    };
}
