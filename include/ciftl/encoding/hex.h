#pragma once

#include <cstdint>

#include <ciftl/encoding/encoding.h>

namespace ciftl
{
    class HexEncoding : public IEncoding
    {
    public:
        enum class Case : uint8_t
        {
            LOWER,
            UPPER
        };

    private:
        Case m_case = Case::UPPER;

    public:
        inline void set_case(Case c)
        {
            m_case = c;
        }

        inline Case get_case() const
        {
            return m_case;
        }

    public:
        HexEncoding(Case c = Case::UPPER);

        std::string encode(const ByteVector &vec) override;

        std::string encode(const byte *data, size_t len) override;

        Result<ByteVector> decode(const std::string &str) override;

        Result<ByteVector> decode(const char *str, size_t len) override;
    };
}
