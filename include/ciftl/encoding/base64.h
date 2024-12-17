#pragma once
#include <cstdint>

#include <ciftl/encoding/encoding.h>

namespace ciftl
{
    class Base64Encoding : public IEncoding
    {
    private:
        static const size_t BLOCK_SIZE = 2048;

    public:
        std::string encode(const ByteVector &vec) override;

        std::string encode(const byte *data, size_t len) override;

        Result<ByteVector> decode(const std::string &str) override;

        Result<ByteVector> decode(const char *str, size_t len) override;
    };
}
