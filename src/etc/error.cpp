#include <ciftl/etc/etc.h>

namespace ciftl
{
    // 11101
    const Error SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH(
        EtcErrorCodeEnum::SrcAndDstMemoryHasDifferentLength,
        "拷贝原始内存和目的内存长度不一致"
    );
    // 11102
    const Error TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION(
        EtcErrorCodeEnum::TwoMemoryHasDifferentLengthWhenXOROperation,
        "进行异或操作的两段内存长度不一致"
    );

    // 11103
    const Error MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT(
        EtcErrorCodeEnum::MemoryTakerHasNoEnoughContent,
        "内存获取器中的内容长度不足"
    );

    // 12101
    const Error HEX_BAD_DECODING_SOURCE(
        EncodingErrorCodeEnum::HexBadDecodingSource,
        "非法的16进制字符串"
    );

    // 12301
    const Error BASE64_BAD_DECODING_SOURCE(
        EncodingErrorCodeEnum::Base64BadDecodingSource,
        "非法的Base64字符串"
    );

    // 13101
    const Error CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH(
        CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedIVLength,
        "不满足要求的IV长度"
    );

    // 13102
    const Error CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH(
        CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedKeyLength,
        "不满足要求的Key长度"
    );

    // 13203
    const Error FAILED_WHEN_FLUSHING_BUFFER(
        CrypterErrorCodeEnum::FailedWhenFlushingBuffer,
        "刷新缓冲区时失败"
    );

    // 13301
    const Error CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING(
        CrypterErrorCodeEnum::CurrentIndexNotAtTheEndOfBufferWhenFlushing,
        "刷新时当前下标不在缓冲区的最后"
    );

    // 13401
    const Error FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT(
        CrypterErrorCodeEnum::FailedWhenCheckingCrc32ValueOfDecryptedContent,
        "解密后内容无法通过校验"
    );

    // 13403
    const Error FAILED_WHEN_DECODING_STRING(
        CrypterErrorCodeEnum::FailedWhenDecodingString,
        "字符串解码时失败"
    );

    // 13404
    const Error CANNOT_DO_CRYPTION_TO_EMPTY_STRING(
        CrypterErrorCodeEnum::CannotDoCryptionToEmptyString,
        "不能对空串进行密码操作"
    );

    // 13405
    const Error PASSWORD_CANNOT_BE_EMPTY(
        CrypterErrorCodeEnum::PasswordCannotBeEmpty,
        "密码不能为空"
    );

    // 13801
    const Error FAILED_WHEN_ENCRYPTING_WITH_BOTAN(
        CrypterErrorCodeEnum::FailedWhenEncryptingWithBotan,
        "使用Botan进行加密时失败"
    );

    // 13901
    const Error FAILED_WHEN_EVP_ENCRYPT_UPDATE(
        CrypterErrorCodeEnum::FailedWhenEVPEncryptUpdate,
        "EVPEncryptUpdate时失败"
    );

    // 13902
    extern const Error FAILED_WHEN_EVP_ENCRYPT_FINAL;
    const Error FAILED_WHEN_EVP_ENCRYPT_FINAL(
        CrypterErrorCodeEnum::FailedWhenEVPEncryptFinal,
        "EVPEncryptFinal时失败"
    );
}
