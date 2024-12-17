#pragma once
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <array>
#include <assert.h>

namespace ciftl
{
    // ByteVector
    typedef uint8_t byte;
    typedef std::vector<byte> ByteVector;

    // ByteArray
    template<size_t ARRAY_SIZE>
    using ByteArray = std::array<byte, ARRAY_SIZE>;

    // CRC32C
    typedef uint32_t Crc32Value;
    typedef ByteArray<sizeof(Crc32Value)> Crc32ByteArray;

    template<class T>
    T auto_cast(const byte *data)
    {
        T t;
        memcpy(reinterpret_cast<byte *>(&t), data, sizeof(T));
        return t;
    }

    template<class T1, class T2>
    T1 auto_cast(const T2 &t2)
    {
    }

    template<>
    inline ByteVector auto_cast(const std::string &str)
    {
        ByteVector res(str.size());
        memcpy(res.data(), str.c_str(), str.size());
        return res;
    }

    template<>
    inline std::string auto_cast(const ByteVector &vec)
    {
        std::string res(vec.size(), '\0');
        memcpy(res.data(), vec.data(), vec.size());
        return res;
    }

    template<>
    inline Crc32Value auto_cast(const ByteVector &vec)
    {
        assert(vec.size() == sizeof(Crc32Value));
        Crc32Value res = 0;
        memcpy(&res, vec.data(), vec.size());
        return res;
    }

    template<>
    inline Crc32Value auto_cast(const ByteArray<sizeof(Crc32Value)> &vec)
    {
        Crc32Value res;
        memcpy(reinterpret_cast<void *>(&res), vec.data(), sizeof(Crc32Value));
        return res;
    }

    template<>
    inline ByteArray<sizeof(Crc32Value)> auto_cast(const Crc32Value &n)
    {
        ByteArray<sizeof(Crc32Value)> res;
        memcpy(res.data(), reinterpret_cast<const void *>(&n), sizeof(Crc32Value));
        return res;
    }

    template<>
    inline ByteVector auto_cast(const Crc32Value &n)
    {
        ByteVector res(sizeof(Crc32Value));
        memcpy(res.data(), reinterpret_cast<const void *>(&n), sizeof(Crc32Value));
        return res;
    }

    // 缓冲区包装器
    class WrappedBuffer
    {
        byte *m_data;
        size_t m_size;

    public:
        WrappedBuffer() = default;

        WrappedBuffer(const WrappedBuffer &other) = default;

        WrappedBuffer(byte *data, size_t size): m_data(data), m_size(size)
        {
        }

        WrappedBuffer &operator=(const WrappedBuffer &other) = default;

        ~WrappedBuffer() = default;

    public:
        byte *data() const noexcept
        {
            return m_data;
        }

        size_t size() const noexcept
        {
            return m_size;
        }
    };


}
