#pragma once
#include <cstring>
#include <memory>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <random>
#include <assert.h>

#include <ciftl/etc/etc.h>
#include <ciftl/hash/hash.h>
#include <ciftl/encoding/encoding.h>

namespace ciftl
{
    ///----------------------------------一些需要的函数----------------------------------///
    /// 加密密码流生成器的不同模式
    /// 该选项会影响到StreamGenerator中的预生成流长度，
    /// 加密短文本时使用Short可以避免生成过长的预生成流
    /// 加密长文件时使用Large可以减少预生成流的生成次数
    enum class StreamGeneratorMode : size_t
    {
        Short = 1,
        Medium = 32,
        Large = 1024
    };

    /// 随机生成IV
    inline void rand_iv(byte *data, size_t len) noexcept
    {
        // 使用随机数引擎和分布来生成随机字节
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < len; ++i) {
            data[i] = (byte) (dis(gen) & 0xFF);
        }
    }

    /// 根据密码生成密钥
    inline void generate_key_from_password(const char *password, byte *data, size_t len) noexcept
    {
        // 生成加密所需的密钥
        Sha256Hasher hasher;
        hasher.update(password);
        ByteVector buffer = hasher.finalize();
        size_t cnt = 0;
        for (; cnt < len;) {
            size_t once_gen = std::min(len - cnt, buffer.size());
            memcpy(data + cnt, buffer.data(), once_gen);
            cnt += once_gen;
            if (cnt >= len) {
                break;
            }
            hasher.update(buffer);
            buffer = hasher.finalize();
        }
    }

    ///----------------------------------相关的trait----------------------------------///
    /// 密码算法trait
    /// 该trait限制T类必须要拥有以下两个函数
    /// 1. T(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len);
    /// 2. crypt(const byte *src_data, size_t src_len, byte *dst_data, size_t dst_len)
    template<typename T>
    class CipherAlgorithmTrait
    {
        template<typename U, typename = void>
        struct has_crypt : std::false_type
        {
        };

        template<typename U>
        struct has_crypt<U, std::void_t<decltype(std::declval<U>().crypt(nullptr, 0, nullptr, 0))> > : std::true_type
        {
        };

        template<typename U, typename = void>
        struct has_key_iv_constructor : std::false_type
        {
        };

        template<typename U>
        struct has_key_iv_constructor<U, std::void_t<decltype(U(nullptr, 0, nullptr, 0))> > : std::true_type
        {
        };

        static_assert(has_crypt<T>::value, "U has no crypt function!");
        static_assert(has_key_iv_constructor<T>::value, "U has no \"key&iv\" constructor!");

    public:
        static constexpr bool value = has_crypt<T>::value && has_key_iv_constructor<T>::value;
    };

    ///----------------------------------相关的接口----------------------------------//
    /// 密码算法接口
    class ICipherAlgorithm
    {
    public:
        virtual Result<void> crypt(const byte *src_data, size_t src_len, byte *dst_data,
                                   size_t dst_len) noexcept = 0;

        virtual size_t iv_length() const noexcept = 0;

        virtual size_t key_length() const noexcept = 0;

        virtual size_t block_length() const noexcept = 0;
    };

    /// 密码流生成器的接口
    class IStreamGenerator
    {
    public:
        // 生成密码流
        virtual Result<void> generate(byte *data, size_t len) noexcept = 0;

        virtual Result<void> generate(ByteVector &data) noexcept = 0;
    };

    /// 字符串加密器接口
    class IStringCrypter
    {
    public:
        virtual Result<std::string> encrypt(const std::string &data,
                                            const std::string &password) noexcept = 0;

        virtual Result<std::string> decrypt(const std::string &data,
                                            const std::string &password) noexcept = 0;
    };

    /// 加密密码流生成器
    /// 密码流生成器有两个关键的参数，一个是IV长度，一个是密钥长度
    /// 所有密码流生成器在继承是都需要指定这两个参数
    /// 同时，为了适用于分组密码，BLOCK_LENGTH也作为可选参数传入，默认为0表示为流密码
    /// 为了避免在将分组密码数组转换成密码流的过程时出现缓冲区大小无法被分组块大小整除的情况（也就是分组在填充到缓冲区时会有剩余）
    /// 这里需要规定缓冲区大小一定是分组长度的倍数
    template<class CA>
    class StreamGenerator : public IStreamGenerator
    {
        // 要求CA一定是实现了CipherAlgorithmTrait
        static_assert(CipherAlgorithmTrait<CA>::value, "CA should satisfy CipherAlgorithmTrait");

    public:
        static constexpr size_t IV_LENGTH = CA::IV_LENGTH;
        static constexpr size_t KEY_LENGTH = CA::KEY_LENGTH;
        static constexpr size_t BLOCK_LENGTH = CA::BLOCK_LENGTH;

        typedef ByteArray<IV_LENGTH> IVByteArray;
        typedef ByteArray<KEY_LENGTH> KeyByteArray;

    public:
        /// 获取不同模式下的缓存区的分组块大小
        static constexpr size_t stream_temp_block_count(StreamGeneratorMode m)
        {
            return static_cast<size_t>(m) * 64;
        }

        /// 获取不同模式下的缓存区大小
        static constexpr size_t stream_temp_buffer_size(StreamGeneratorMode m)
        {
            if (BLOCK_LENGTH) {
                return stream_temp_block_count(m) * BLOCK_LENGTH;
            }
            return static_cast<size_t>(m) * 1024;
        }

        /// 随机生成IV
        static IVByteArray rand_iv()
        {
            IVByteArray iv_bytes;
            ::ciftl::rand_iv(iv_bytes.data(), iv_bytes.size());
            return iv_bytes;
        }

        /// 根据密码生成密钥
        static KeyByteArray generate_key_from_password(const std::string &password)
        {
            // 生成加密所需的密钥
            KeyByteArray key;
            ::ciftl::generate_key_from_password(password.c_str(), key.data(), key.size());
            return key;
        }

    public:
        StreamGenerator(const byte *iv_data, size_t iv_len, const byte *key_data, size_t key_len,
                        StreamGeneratorMode mode = StreamGeneratorMode::Medium,
                        std::function<size_t(StreamGeneratorMode)> assign_buffer_size = stream_temp_buffer_size)
            : m_cipher_algorithm(iv_data, iv_len, key_data, key_len),
              m_mode(mode),
              m_max_buffer_size(assign_buffer_size(mode)),
              m_current_index(0L),
              m_current_buffer(std::make_unique<byte[]>(m_max_buffer_size)),
              m_plaintext_buffer(std::make_unique<byte[]>(m_max_buffer_size)),
              m_is_flush_init(false)
        {
            memset(m_plaintext_buffer.get(), 0x00, m_max_buffer_size);
        }

        ~StreamGenerator() = default;

    private:
        Result<void> flush()
        {
            if (this->m_current_index != this->m_max_buffer_size && this->m_is_flush_init) {
                return Result<void>::make_err(FAILED_WHEN_FLUSHING_BUFFER);
            }
            this->m_current_index = 0;
            return m_cipher_algorithm.crypt(m_plaintext_buffer.get(), m_max_buffer_size, m_current_buffer.get(),
                                            this->m_max_buffer_size);
        }

    public:
        /// 生成加密流
        Result<void> generate(byte *data, size_t len) noexcept override
        {
            // 初始化刷新
            if (!m_is_flush_init) {
                if (auto res = flush(); res.is_err()) {
                    return res;
                }
                m_is_flush_init = true;
            }
            size_t index = 0L;
            size_t once_gen = m_max_buffer_size - m_current_index;
            // 如果要产生新的buffer，则不断的循环这一步骤
            for (; index + once_gen < len;) {
                memcpy(data + index, m_current_buffer.get() + m_current_index, once_gen);
                index += once_gen;
                m_current_index += once_gen;
                if (auto res = flush(); res.is_err()) {
                    return res;
                }
                once_gen = m_max_buffer_size - m_current_index;
            }
            size_t last_gen = len - index;
            memcpy(data + index, m_current_buffer.get() + m_current_index, last_gen);
            index += last_gen;
            m_current_index += last_gen;
            return Result<void>::make_ok(len);
        }

        /// 生成密码流
        Result<void> generate(ByteVector &data) noexcept override
        {
            return generate(data.data(), data.size());
        }

    protected:
        /// 使用的密码算法
        CA m_cipher_algorithm;
        /// 缓冲区最大容量
        const size_t m_max_buffer_size;
        /// 流生成模式
        StreamGeneratorMode m_mode;
        size_t m_current_index;
        /// 当前的密码流缓冲区
        std::unique_ptr<byte[]> m_current_buffer;
        /// 用于作为加密原文的明文缓冲区
        std::unique_ptr<byte[]> m_plaintext_buffer;
        /// 密码流生成器使用的IV和Key
        bool m_is_flush_init;
    };

    /// 字符串加密器
    /// StringCrypter基于StreamGenerator实现了对一段文本的加密，每次调用都是独立的
    /// StringCrypter密文格式
    /// |-----------IV（长度取决于加密算法）-----|----CRC32（4字节，会在最后被加密）-----|--------密文（使用StreamGenerator进行加密）--------|
    /// 暴露的信息只有IV，解密时通过IV和密码生成的Key来初始化StreamGenerator
    template<class CA>
    class StringCrypter : public IStringCrypter
    {
    public:
        static constexpr size_t IV_LENGTH = CA::IV_LENGTH;
        static constexpr size_t KEY_LENGTH = CA::KEY_LENGTH;
        static constexpr size_t BLOCK_LENGTH = CA::BLOCK_LENGTH;

        typedef ByteArray<IV_LENGTH> IVByteArray;
        typedef ByteArray<KEY_LENGTH> KeyByteArray;

    public:
        /// 随机生成IV
        static IVByteArray rand_iv()
        {
            IVByteArray iv_bytes;
            ::ciftl::rand_iv(iv_bytes.data(), iv_bytes.size());
            return iv_bytes;
        }

        /// 根据密码生成密钥
        static KeyByteArray generate_key_from_password(const std::string &password)
        {
            // 生成加密所需的密钥
            KeyByteArray key;
            ::ciftl::generate_key_from_password(password.c_str(), key.data(), key.size());
            return key;
        }

    public:
        Result<std::string> encrypt(const std::string &data,
                                    const std::string &password) noexcept override
        {
            if (data.empty()) {
                return Result<std::string>::make_err(CANNOT_DO_CRYPTION_TO_EMPTY_STRING);
            }
            if (password.empty()) {
                return Result<std::string>::make_err(PASSWORD_CANNOT_BE_EMPTY);
            }
            // 创建一个密码流生成器
            auto iv = rand_iv();
            auto key = generate_key_from_password(password);
            StreamGenerator<CA> stream_generator(iv.data(), iv.size(),
                                                 key.data(), key.size(),
                                                 StreamGeneratorMode::Short);
            // 获取明文的字节流
            byte *plain_data_bytes = (byte *) data.data();
            size_t plain_data_bytes_len = data.size();
            // 获取明文的校验值
            Crc32cHasher hasher;
            hasher.update(data);
            auto plain_data_checksum = hasher.finalize();
            auto plain_data_checksum_len = plain_data_checksum.size();
            // 生成密码流进行加密
            auto cipher_data_bytes = std::make_unique<byte[]>(plain_data_bytes_len);
            // 处理加密时错误
            if (auto generate_result = stream_generator.generate(cipher_data_bytes.get(), plain_data_bytes_len);
                generate_result.is_err()) {
                return Result<std::string>::make_err(std::move(generate_result.unwrap_err()));
            }
            // 异或加密内容主体
            for (size_t i = 0; i < plain_data_bytes_len; i++) {
                cipher_data_bytes[i] = plain_data_bytes[i] ^ cipher_data_bytes[i];
            }
            // 继续加密校验值
            auto cipher_data_checksum = std::make_unique<byte[]>(plain_data_checksum_len);
            if (auto generate_result = stream_generator.generate(cipher_data_checksum.get(), plain_data_checksum_len);
                generate_result.is_err()) {
                return Result<std::string>::make_err(std::move(generate_result.unwrap_err()));
            }
            // 异或加密checksum
            for (size_t i = 0; i < plain_data_checksum_len; i++) {
                cipher_data_checksum[i] = plain_data_checksum[i] ^ cipher_data_checksum[i];
            }
            auto result_vec = concat(std::move(iv),
                                     WrappedBuffer(cipher_data_checksum.get(), plain_data_checksum_len),
                                     WrappedBuffer(cipher_data_bytes.get(), plain_data_bytes_len));
            // 对结果进行base64编码
            Base64Encoding base64_encoding;
            return Result<std::string>::make_ok(base64_encoding.encode(result_vec));
        }

        Result<std::string> decrypt(const std::string &data,
                                    const std::string &password) noexcept override
        {
            if (data.empty()) {
                return Result<std::string>::make_err(CANNOT_DO_CRYPTION_TO_EMPTY_STRING);
            }
            if (password.empty()) {
                return Result<std::string>::make_err(PASSWORD_CANNOT_BE_EMPTY);
            }
            // 对密文进行解码
            Base64Encoding base64_encoding;
            auto result_data_bytes = base64_encoding.decode(data);
            if (result_data_bytes.is_err()) {
                return Result<std::string>::make_err(std::move(result_data_bytes.unwrap_err()));
            }
            // 从原文中获取数据
            auto data_bytes = std::move(result_data_bytes.unwrap());
            // 准备分配cipher中的内容
            ByteVector iv(IV_LENGTH);
            ByteVector cipher_data_checksum(sizeof(Crc32Value));
            size_t cipher_data_checksum_len = cipher_data_checksum.size();
            ByteVector cipher_data_bytes;
            // 使用MemoryTaker获取内容
            MemoryTaker mt(data_bytes.data(), data_bytes.size());
            if (auto res = mt.take(iv); res.is_err()) {
                return Result<std::string>::make_err(std::move(res.unwrap_err()));
            }
            if (auto res = mt.take(cipher_data_checksum); res.is_err()) {
                return Result<std::string>::make_err(std::move(res.unwrap_err()));
            }
            if (auto res = mt.take_all(); res.is_err()) {
                return Result<std::string>::make_err(std::move(res.unwrap_err()));
            } else {
                cipher_data_bytes = std::move(res.unwrap());
            }
            size_t cipher_data_bytes_len = cipher_data_bytes.size();
            // 根据密码计算出密钥
            auto key = generate_key_from_password(password);
            StreamGenerator<CA> stream_generator(iv.data(), iv.size(),
                                                 key.data(), key.size(),
                                                 StreamGeneratorMode::Short);
            // 生成密码流进行解密
            auto plain_data_bytes = std::make_unique<byte[]>(cipher_data_bytes_len);
            auto generate_result = stream_generator.generate(plain_data_bytes.get(), cipher_data_bytes_len);
            // 处理解密时错误
            if (generate_result.is_err()) {
                return Result<std::string>::make_err(std::move(generate_result.unwrap_err()));
            }
            // 异或解密内容主体
            for (size_t i = 0; i < cipher_data_bytes_len; i++) {
                plain_data_bytes[i] = plain_data_bytes[i] ^ cipher_data_bytes[i];
            }
            // 继续解密校验值
            auto plain_data_checksum = std::make_unique<byte[]>(cipher_data_checksum_len);
            if (auto generate_result = stream_generator.generate(plain_data_checksum.get(), cipher_data_checksum_len);
                generate_result.is_err()) {
                return Result<std::string>::make_err(std::move(generate_result.unwrap_err()));
            }
            // 异或解密checksum主体
            for (size_t i = 0; i < cipher_data_checksum_len; i++) {
                plain_data_checksum[i] = plain_data_checksum[i] ^ cipher_data_checksum[i];
            }
            // 获取明文的校验值
            Crc32cHasher hasher;
            hasher.update(plain_data_bytes.get(), cipher_data_bytes_len);
            auto cipher_data_checksum_decrypted = hasher.finalize();
            // 比较前后的校验和
            if (memcmp(plain_data_checksum.get(), cipher_data_checksum_decrypted.data(), cipher_data_checksum_len)) {
                return Result<std::string>::make_err(FAILED_WHEN_CHECKING_CRC32_VALUE_OF_DECRYPTED_CONTENT);
            }
            ByteVector result_vec(cipher_data_bytes_len);
            memcpy(result_vec.data(), plain_data_bytes.get(), cipher_data_bytes_len);
            return Result<std::string>::make_ok(auto_cast<std::string, ByteVector>(result_vec));
        }
    };
}
