#pragma once
#include <memory>
#include <string>
#include <vector>

#include <ciftl/etc/etc.h>

namespace ciftl
{
    class IEncoding
    {
    public:
        virtual std::string encode(const ByteVector &vec) = 0;

        virtual std::string encode(const byte *data, size_t len) = 0;

        virtual Result<ByteVector> decode(const std::string &str) = 0;

        virtual Result<ByteVector> decode(const char *str, size_t len) = 0;
    };
}
