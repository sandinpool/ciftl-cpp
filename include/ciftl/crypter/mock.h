#pragma once
#include <ciftl/etc/etc.h>
#include <ciftl/crypter/core_crypter.h>

namespace ciftl
{
    class MockCipherAlgorithm
    {
    public:
        static constexpr size_t IV_LENGTH = 16;
        static constexpr size_t KEY_LENGTH = 16;
        static constexpr size_t BLOCK_LENGTH = 16;

        MockCipherAlgorithm(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len)
        {
            assert(iv_len == IV_LENGTH);
            assert(key_len == KEY_LENGTH);
        }

        Result<void> crypt(const byte *src_data, size_t src_len, byte *dst_data, size_t dst_len)
        {
            if (src_len != dst_len) {
                return Result<void>::make_err(SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH);
            }
            for (int i = 0; i < dst_len; i += 1) {
                dst_data[i] = 'M';
            }
            return Result<void>::make_ok();
        }
    };
}
