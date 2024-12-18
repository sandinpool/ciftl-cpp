#pragma once
#include <ciftl/etc/result.h>

namespace ciftl
{
    // ErrorCodeEnum: 错误码分类枚举
    // 每个类别有一个基础值，后续的错误码通过加上偏移量生成。
    enum class ErrorCodeEnum : ErrorCode
    {
        // 错误码的起始基值
        ErrorCodeBase = 10000,

        // etc错误分类
        EtcError = ErrorCodeEnum::ErrorCodeBase + 1 * 1000,

        // 编码错误分类
        EncodingError = ErrorCodeEnum::ErrorCodeBase + 2 * 1000,

        // 加密错误分类
        CrypterError = ErrorCodeEnum::ErrorCodeBase + 3 * 1000,
    };

    // EtcErrorCodeEnum: 与EtcError相关的错误码
    // 包含了一些特定的内存操作错误码，如拷贝内存长度不一致等。
    enum class EtcErrorCodeEnum : ErrorCode
    {
        // 容器相关的错误
        ContainerError = static_cast<ErrorCode>(ErrorCodeEnum::EtcError) + 1 * 100,

        // 拷贝原始内存和目的内存长度不一致
        SrcAndDstMemoryHasDifferentLength,

        // 两段内存进行异或操作时长度不一致
        TwoMemoryHasDifferentLengthWhenXOROperation,

        // 内存获取器中的内容长度不足
        MemoryTakerHasNoEnoughContent,
    };

    // EncodingErrorCodeEnum: 与编码相关的错误码
    // 包括Hex编码、Bin编码、Base64编码的错误。
    enum class EncodingErrorCodeEnum : ErrorCode
    {
        // Hex编码错误
        HexEncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 1 * 100,

        // Hex编码失败，源数据格式不正确
        HexBadDecodingSource,

        // Bin编码错误
        BinEncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 2 * 100,

        // Base64编码错误
        Base64EncodingError = static_cast<ErrorCode>(ErrorCodeEnum::EncodingError) + 3 * 100,

        // Base64编码失败，源数据格式不正确
        Base64BadDecodingSource,
    };

    // CrypterErrorCodeEnum: 与加密相关的错误码
    // 包括密码算法错误、流生成器错误、字符串加密错误等。
    enum class CrypterErrorCodeEnum : ErrorCode
    {
        // 密码算法相关的错误
        CipherAlgorithmError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 1 * 100,

        // IV长度不符合密码算法要求
        CipherAlgorithmUnsatisfiedIVLength,

        // Key长度不符合密码算法要求
        CipherAlgorithmUnsatisfiedKeyLength,

        // 流生成器相关的错误
        StreamGeneratorError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 2 * 100,

        // 执行密码操作时失败
        FailedWhenCrypting,

        // 完成密码操作时失败
        FailedWhenFinalizingCryption,

        // 刷新缓冲区时失败
        FailedWhenFlushingBuffer,

        // 流加密器相关的错误
        StreamCrypterError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 3 * 100,

        // 刷新时当前下标不在缓冲区的最后
        CurrentIndexNotAtTheEndOfBufferWhenFlushing,

        // 字符串加密相关的错误
        StringCrypterError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 4 * 100,

        // 解密后内容无法通过CRC32校验
        FailedWhenCheckingCrc32ValueOfDecryptedContent,

        // 字符串编码时失败
        FailedWhenEncodingString,

        // 字符串解码时失败
        FailedWhenDecodingString,

        // 不能对空字符串进行密码操作
        CannotDoCryptionToEmptyString,

        // 密码不能为空
        PasswordCannotBeEmpty,

        // OpenSSL相关的错误
        OpenSSLError = static_cast<ErrorCode>(ErrorCodeEnum::CrypterError) + 8 * 100,

        // EVPEncryptUpdate失败
        FailedWhenEVPEncryptUpdate,

        // EVPEncryptFinal失败
        FailedWhenEVPEncryptFinal,
    };

    // 以下是对应错误消息的宏定义，用于描述具体的错误信息。

    // 11101 错误消息: 拷贝原始内存和目的内存长度不一致
#define SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH_MESSAGE "拷贝原始内存和目的内存长度不一致"

    // 11102 错误消息: 进行异或操作的两段内存长度不一致
#define TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION_MESSAGE "进行异或操作的两段内存长度不一致"

    // 11103 错误消息: 内存获取器中的内容长度不足
#define MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT_MESSAGE "内存获取器中的内容长度不足"

    // 12101 错误消息: 非法的16进制字符串
#define HEX_BAD_DECODING_SOURCE_MESSAGE "非法的16进制字符串"

    // 12301 错误消息: 非法的Base64字符串
#define BASE64_BAD_DECODING_SOURCE_MESSAGE "非法的Base64字符串"

    // 13101 错误消息: 不满足要求的IV长度
#define CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH_MESSAGE "不满足要求的IV长度"

    // 13102 错误消息: 不满足要求的Key长度
#define CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH_MESSAGE "不满足要求的Key长度"

    // 13203 错误消息: 刷新缓冲区时失败
#define FAILED_WHEN_FLUSHING_BUFFER_MESSAGE "刷新缓冲区时失败"

    // 13301 错误消息: 刷新时当前下标不在缓冲区的最后
#define CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING_MESSAGE "刷新时当前下标不在缓冲区的最后"

    // 13401 错误消息: 解密后内容无法通过校验
#define FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT_MESSAGE "解密后内容无法通过校验"

    // 13403 错误消息: 字符串解码时失败
#define FAILED_WHEN_DECODING_STRING_MESSAGE "字符串解码时失败"

    // 13404 错误消息: 不能对空串进行密码操作
#define CANNOT_DO_CRYPTION_TO_EMPTY_STRING_MESSAGE "不能对空串进行密码操作"

    // 13405 错误消息: 密码不能为空
#define PASSWORD_CANNOT_BE_EMPTY_MESSAGE "密码不能为空"

    // 13801 错误消息: EVPEncryptUpdate时失败
#define FAILED_WHEN_EVP_ENCRYPT_UPDATE_MESSAGE "EVPEncryptUpdate时失败"

    // 13802 错误消息: EVPEncryptFinal时失败
#define FAILED_WHEN_EVP_ENCRYPT_FINAL_MESSAGE "EVPEncryptFinal时失败"

    // 以下是具体的错误定义，使用宏将错误码与错误消息绑定，方便后续使用。

    // 11101 错误定义: 拷贝原始内存和目的内存长度不一致
#define SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH \
        Error(EtcErrorCodeEnum::SrcAndDstMemoryHasDifferentLength, \
        SRC_AND_DST_MEMORY_HAS_DIFFERENT_LENGTH_MESSAGE)

    // 11102 错误定义: 进行异或操作的两段内存长度不一致
#define TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION \
        Error(EtcErrorCodeEnum::TwoMemoryHasDifferentLengthWhenXOROperation, \
        TWO_MEMORY_HAS_DIFFERENT_LENGTH_WHEN_XOR_OPERATION_MESSAGE)

    // 11103 错误定义: 内存获取器中的内容长度不足
#define MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT \
        Error(EtcErrorCodeEnum::MemoryTakerHasNoEnoughContent, \
        MEMORY_TAKER_HAS_NO_ENOUGH_CONTENT_MESSAGE)

    // 12101 错误定义: 非法的16进制字符串
#define HEX_BAD_DECODING_SOURCE \
        Error(EncodingErrorCodeEnum::HexBadDecodingSource, \
        HEX_BAD_DECODING_SOURCE_MESSAGE)

    // 12301 错误定义: 非法的Base64字符串
#define BASE64_BAD_DECODING_SOURCE \
        Error(EncodingErrorCodeEnum::Base64BadDecodingSource, \
        BASE64_BAD_DECODING_SOURCE_MESSAGE)

    // 13101 错误定义: 不满足要求的IV长度
#define CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH \
        Error(CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedIVLength, \
        CIPHER_ALGORITHM_UNSATISFIED_IV_LENGTH_MESSAGE)

    // 13102 错误定义: 不满足要求的Key长度
#define CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH \
        Error(CrypterErrorCodeEnum::CipherAlgorithmUnsatisfiedKeyLength, \
        CIPHER_ALGORITHM_UNSATISFIED_KEY_LENGTH_MESSAGE)

    // 13203 错误定义: 刷新缓冲区时失败
#define FAILED_WHEN_FLUSHING_BUFFER \
        Error(CrypterErrorCodeEnum::FailedWhenFlushingBuffer, \
        FAILED_WHEN_FLUSHING_BUFFER_MESSAGE)

    // 13301 错误定义: 刷新时当前下标不在缓冲区的最后
#define CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING \
        Error(CrypterErrorCodeEnum::CurrentIndexNotAtTheEndOfBufferWhenFlushing, \
        CURRENT_INDEX_NOT_AT_THE_END_OF_BUFFER_WHEN_FLUSHING_MESSAGE)

    // 13401 错误定义: 解密后内容无法通过校验
#define FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT \
        Error(CrypterErrorCodeEnum::FailedWhenCheckingCrc32ValueOfDecryptedContent, \
        FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT_MESSAGE)

    // 13403 错误定义: 字符串解码时失败
#define FAILED_WHEN_DECODING_STRING \
        Error(CrypterErrorCodeEnum::FailedWhenDecodingString, \
        FAILED_WHEN_DECODING_STRING_MESSAGE)

    // 13404 错误定义: 不能对空串进行密码操作
#define CANNOT_DO_CRYPTION_TO_EMPTY_STRING \
        Error(CrypterErrorCodeEnum::CannotDoCryptionToEmptyString, \
        CANNOT_DO_CRYPTION_TO_EMPTY_STRING_MESSAGE)

    // 13405 错误定义: 密码不能为空
#define PASSWORD_CANNOT_BE_EMPTY \
        Error(CrypterErrorCodeEnum::PasswordCannotBeEmpty, \
        PASSWORD_CANNOT_BE_EMPTY_MESSAGE)

    // 13801 错误定义: EVPEncryptUpdate时失败
#define FAILED_WHEN_EVP_ENCRYPT_UPDATE \
        Error(CrypterErrorCodeEnum::FailedWhenEVPEncryptUpdate, \
        FAILED_WHEN_EVP_ENCRYPT_UPDATE_MESSAGE)

    // 13802 错误定义: EVPEncryptFinal时失败
#define FAILED_WHEN_EVP_ENCRYPT_FINAL \
        Error(CrypterErrorCodeEnum::FailedWhenEVPEncryptFinal, \
        FAILED_WHEN_EVP_ENCRYPT_FINAL_MESSAGE)
}
