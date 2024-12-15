#pragma once
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <botan/stream_cipher.h>

#include <ciftl/crypter/crypter.h>
#include <ciftl/etc/etc.h>

namespace ciftl
{
    ChaCha20CipherAlgorithm::ChaCha20CipherAlgorithm(const byte *iv_data, size_t iv_len,
                                                     const byte *key_data, size_t key_len)
        : m_botan_chacha20(Botan::StreamCipher::create_or_throw("ChaCha20"))
    {
        assert(iv_len == IV_LENGTH);
        assert(key_len == KEY_LENGTH);
        m_botan_chacha20->set_key(key_data, key_len);
        m_botan_chacha20->set_iv(iv_data, iv_len);
    }

    Result<void> ChaCha20CipherAlgorithm::crypt(const byte *src_data, size_t src_len, byte *dst_data,
                                                size_t dst_len) noexcept
    {
        if (src_len != dst_len) {
            return Result<void>::make_err(SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH);
        }
        // 用span包装dst_data
        std::span<byte> temp_buffer(dst_data, dst_len);
        memcpy(temp_buffer.data(), src_data, src_len);
        try {
            // 执行加密，这里是对m_plaintext_buffer进行加密，并将结果拷贝到temp_buffer中
            m_botan_chacha20->encipher(temp_buffer);
        } catch (...) {
            return Result<void>::make_err(FAILED_WHEN_ENCRYPTING_WITH_BOTAN);
        }
        return Result<void>::make_ok();
    }
}
