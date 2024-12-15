#pragma once
#include <ciftl/etc/result.h>

namespace ciftl
{
    // 错误码分类
    enum class ErrorCodeEnum : ErrorCode
    {
        // 错误码起始值
        ErrorCodeBase = 10000,
        // etc错误
        EtcError = ErrorCodeEnum::ErrorCodeBase + 1 * 1000,
        // 编码器错误段
        EncodingError = ErrorCodeEnum::ErrorCodeBase + 2 * 1000,
        // 加密器错误段
        CrypterError = ErrorCodeEnum::ErrorCodeBase + 3 * 1000,
    };

    // etc错误
    enum class EtcErrorCodeEnum : ErrorCode
    {
        // 容器的错误段
        ContainerError = static_cast<ErrorCode>(ErrorCodeEnum::EtcError) + 1 * 100,
        // 拷贝原始内存和目的内存长度不一致
        SrcAndDstMemoryHasDifferentLength,
        // 进行异或操作的两段内存长度不一致
        TwoMemoryHasDifferentLengthWhenXOROperation,
        // 内存获取器中的内容长度不足
        MemoryTakerHasNoEnoughContent,
    };

    // 编码错误码
    enum class EncodingErrorCodeEnum : ErrorCode
    {
        // Hex的错误段
        HexEncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 1 * 100,
        HexBadDecodingSource,
        // Bin的错误段
        BinEncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 2 * 100,
        // Base64的错误段
        Base64EncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 3 * 100,
        Base64BadDecodingSource,
    };

    // 加密器错误码
    enum class CrypterErrorCodeEnum : ErrorCode
    {
        // 密码算法错误段
        CipherAlgorithmError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 1 * 100,
        // 不满足要求的IV长度
        CipherAlgorithmUnsatisfiedIVLength,
        // 不满足要求的Key长度
        CipherAlgorithmUnsatisfiedKeyLength,
        // 流生成器错误段
        StreamGeneratorError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 2 * 100,
        // 执行密码操作时失败
        FailedWhenCrypting,
        // 完成密码操作时失败
        FailedWhenFinalizingCryption,
        // 刷新缓冲区时失败
        FailedWhenFlushingBuffer,
        // 流加密器错误段
        StreamCrypterError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 3 * 100,
        // 刷新时当前下标不在缓冲区的最后
        CurrentIndexNotAtTheEndOfBufferWhenFlushing,
        // 字符串加密器错误段
        StringCrypterError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 4 * 100,
        // 解密后内容无法通过校验
        FailedWhenCheckingCrc32ValueOfDecryptedContent,
        // 字符串编码时失败
        FailedWhenEncodingString,
        // 字符串解码时失败
        FailedWhenDecodingString,
        // 不能对空串进行密码操作
        CannotDoCryptionToEmptyString,
        // 密码不能为空
        PasswordCannotBeEmpty,
        // Botan错误段
        BotanError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 8 * 100,
        // 使用Botan进行加密时失败
        FailedWhenEncryptingWithBotan,
        // OpenSSL错误段
        OpenSSLError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 9 * 100,
        // EVPEncryptUpdate时失败
        FailedWhenEVPEncryptUpdate,
        // EVPEncryptFinal时失败
        FailedWhenEVPEncryptFinal,
    };

    // 错误码: 11101, 错误信息: 拷贝原始内存和目的内存长度不一致
    extern const Error SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH;

    // 错误码: 11102, 错误信息: 进行异或操作的两段内存长度不一致
    extern const Error TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION;

    // 错误码: 11103, 错误信息: 内存获取器中的内容长度不足
    extern const Error MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT;

    // 错误码: 12101, 错误信息: 非法的16进制字符串
    extern const Error HEX_BAD_DECODING_SOURCE;

    // 错误码: 12301, 错误信息: 非法的Base64字符串
    extern const Error BASE64_BAD_DECODING_SOURCE;

    // 错误码: 13101, 错误信息: 不满足要求的IV长度
    extern const Error CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH;

    // 错误码: 13102, 错误信息: 不满足要求的Key长度
    extern const Error CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH;

    // 错误码: 13203, 错误信息: 刷新缓冲区时失败
    extern const Error FAILED_WHEN_FLUSHING_BUFFER;

    // 错误码: 13301, 错误信息: 刷新时当前下标不在缓冲区的最后
    extern const Error CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING;

    // 错误码: 13401, 错误信息: 解密后内容无法通过校验
    extern const Error FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT;

    // 错误码: 13403, 错误信息: 字符串解码时失败
    extern const Error FAILED_WHEN_DECODING_STRING;

    // 错误码: 13404, 错误信息: 不能对空串进行密码操作
    extern const Error CANNOT_DO_CRYPTION_TO_EMPTY_STRING;

    // 错误码: 13405, 错误信息: 密码不能为空
    extern const Error PASSWORD_CANNOT_BE_EMPTY;

    // 错误码: 13801, 错误信息: 使用Botan进行加密时失败
    extern const Error FAILED_WHEN_ENCRYPTING_WITH_BOTAN;

    // 错误码: 13901, 错误信息: EVPEncryptUpdate时失败
    extern const Error FAILED_WHEN_EVP_ENCRYPT_UPDATE;

    // 错误码: 13902, 错误信息: EVPEncryptFinal时失败
    extern const Error FAILED_WHEN_EVP_ENCRYPT_FINAL;
}
